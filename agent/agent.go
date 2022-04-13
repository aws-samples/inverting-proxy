/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*

Copyright 2016 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command agent forwards requests from an inverting proxy to a backend server.
//
// To build, run:
//
//    $ make
//
// And to use, run:
//
//    $ $(GOPATH)/bin/proxy-forwarding-agent -proxy <proxy-url> -backend <backend-ID>

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/golang/groupcache/lru"
	uuid "github.com/nu7hatch/gouuid"
	"golang.org/x/net/publicsuffix"

	"github.com/google/inverting-proxy/agent/banner"
	"github.com/google/inverting-proxy/agent/metrics"
	"github.com/google/inverting-proxy/agent/sessions"
	"github.com/google/inverting-proxy/agent/utils"
	"github.com/google/inverting-proxy/agent/websockets"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	requestCacheLimit   = 1000
	emailScope          = "email"
	headerAuthorization = "Authorization"
)

var (
	proxy                     = flag.String("proxy", "", "URL (including scheme) of the inverting proxy")
	proxyTimeout              = flag.Duration("proxy-timeout", 60*time.Second, "Client timeout when sending requests to the inverting proxy")
	host                      = flag.String("host", "localhost:8080", "Hostname (including port) of the backend server")
	scheme                    = flag.String("scheme", "http", "HTTP or HTTPS")
	backendID                 = flag.String("backend", "", "Unique ID for this backend.")
	debug                     = flag.Bool("debug", false, "Whether or not to print debug log messages")
	disableSSLForTest         = flag.Bool("disable-ssl-for-test", false, "Disable requirements for SSL when running tests locally")
	favIconURL                = flag.String("favicon-url", "", "URL of the favicon")
	forwardUserID             = flag.Bool("forward-user-id", false, "Whether or not to include the ID (email address) of the end user in requests to the backend")
	injectBanner              = flag.String("inject-banner", "", "HTML snippet to inject in served webpages")
	bannerHeight              = flag.String("banner-height", "40px", "Height of the injected banner. This is ignored if no banner is set.")
	shimWebsockets            = flag.Bool("shim-websockets", false, "Whether or not to replace websockets with a shim")
	shimPath                  = flag.String("shim-path", "", "Path under which to handle websocket shim requests")
	healthCheckPath           = flag.String("health-check-path", "/", "Path on backend host to issue health checks against.  Defaults to the root.")
	healthCheckFreq           = flag.Int("health-check-interval-seconds", 0, "Wait time in seconds between health checks.  Set to zero to disable health checks.  Checks disabled by default.")
	healthCheckUnhealthy      = flag.Int("health-check-unhealthy-threshold", 2, "A so-far healthy backend will be marked unhealthy after this many consecutive failures. The minimum value is 1.")
	disableEC2                = flag.Bool("disable-aws-vm-header", false, "Disable the agent from adding AWS EC2 header.")
	enableWebsocketsInjection = flag.Bool("enable-websockets-injection", false, "Enables the injection of HTTP headers into websocket messages. "+
		"Websocket message injection will inject all headers from the HTTP request to /data and inject them "+
		"into JSON-serialized websocket messages at the JSONPath `resource.headers`")

	sessionCookieName       = flag.String("session-cookie-name", "", "Name of the session cookie; an empty value disables agent-based session tracking")
	sessionCookieTimeout    = flag.Duration("session-cookie-timeout", 12*time.Hour, "Expiration flag for the session cookie")
	sessionCookieCacheLimit = flag.Int("session-cookie-cache-limit", 1000, "Upper bound on the number of concurrent sessions that can be tracked by the agent")
	rewriteWebsocketHost    = flag.Bool("rewrite-websocket-host", false, "Whether to rewrite the Host header to the original request when shimming a websocket connection")
	stripCredentials        = flag.Bool("strip-credentials", false, "Whether to strip the Authorization header from all requests.")

	SDNamespace = flag.String("SDnamespaceID", "", "Service discovery namespace id for CloudMap")
	SDService   = flag.String("SDService", "", "Service name for CloudMap")

	namespace = flag.String("namespace", "", "Monitoring metric namespace")

	awsaccesskey = flag.String("access-key", "", "AWS Access Key")
	awssecret    = flag.String("secret", "", "AWS Secret")
	region       = flag.String("region", "", "AWS Region")

	sessionLRU    *sessions.Cache
	metricHandler *metrics.MetricHandler

	AWSConfig aws.Config
	proxyIP   string
)

func hostProxy(ctx context.Context, host, shimPath string, injectShimCode bool) (http.Handler, error) {

	hostProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: *scheme,
		Host:   host,
	})

	hostProxy.FlushInterval = 100 * time.Millisecond
	var h http.Handler = hostProxy
	h = sessionLRU.SessionHandler(h, metricHandler)
	if shimPath != "" {
		var err error
		// Note that we pass in the sessionHandler to the websocket proxy twice (h and sessionLRU.SessionHandler)
		// h is the wrapped handler that will handle all non-websocket-shim requests
		// sessionLRU.SessionHandler will be called for websocket open requests
		// This is necessary to handle an edge case in session handling. Websocket open requests arrive with a path
		// of `/$shimPath/open`. The original target URL and path are encoded in the request body, which is
		// restored in the websocket handler. This means that attempting to restore session cookies that are
		// restricted to a path prefix not equal to "/" will fail for websocket open requests. Passing in the
		// sessionHandler twice allows the websocket handler to ensure that cookies are applied based on the
		// correct, restored path.
		h, err = websockets.Proxy(ctx, h, host, shimPath, *rewriteWebsocketHost, *enableWebsocketsInjection, sessionLRU.SessionHandler, metricHandler)
		if injectShimCode {
			shimFunc, err := websockets.ShimBody(shimPath)
			if err != nil {
				return nil, err
			}
			hostProxy.ModifyResponse = shimFunc
		}
		if err != nil {
			return nil, err
		}
	}
	if *injectBanner == "" {
		return h, nil
	}
	return banner.Proxy(ctx, h, *injectBanner, *bannerHeight, *favIconURL, metricHandler)
}

// forwardRequest forwards the given request from the proxy to
// the backend server and reports the response back to the proxy.
func forwardRequest(client *http.Client, hostProxy http.Handler, request *utils.ForwardedRequest) error {
	httpRequest := request.Contents
	if *debug {
		log.Printf("Request %s: %s %s %v\n", request.RequestID, request.Contents.Method, request.Contents.Host, request.Contents.ContentLength)
	}
	if *forwardUserID {
		httpRequest.Header.Add(utils.HeaderUserID, request.User)
	}
	if *stripCredentials {
		httpRequest.Header.Del(headerAuthorization)
	}
	responseForwarder, err := utils.NewResponseForwarder(client, *proxy, request.BackendID, request.RequestID)
	if err != nil {
		return fmt.Errorf("failed to create the response forwarder: %v", err)
	}
	hostProxy.ServeHTTP(responseForwarder, httpRequest)
	if *debug {
		log.Printf("Backend latency for request %s: %s\n", request.RequestID, time.Since(request.StartTime).String())
	}
	if err := responseForwarder.Close(); err != nil {
		return fmt.Errorf("failed to close the response forwarder: %v", err)
	}
	return nil
}

// healthCheck issues a health check against the backend server
// and returns the result.
func healthCheck() error {
	resp, err := http.Get(*scheme + "://" + *host + *healthCheckPath)
	if err != nil {
		log.Printf("Health Check request failed: %s", err.Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("Health Check request had non-200 status code: %d", resp.StatusCode)
		return fmt.Errorf("Bad Health Check Response Code: %s", resp.Status)
	}
	return nil
}

// processOneRequest reads a single request from the proxy and forwards it to the backend server.
func processOneRequest(client *http.Client, hostProxy http.Handler, backendID string, requestID string) {
	requestForwarder := func(client *http.Client, request *utils.ForwardedRequest) error {
		if err := forwardRequest(client, hostProxy, request); err != nil {
			log.Printf("Failure forwarding a request: [%s] %q\n", requestID, err.Error())
			return fmt.Errorf("failed to forward the request %q: %v", requestID, err)
		}
		return nil
	}
	if err := utils.ReadRequest(client, *proxy, backendID, requestID, requestForwarder, metricHandler); err != nil {
		log.Printf("Failed to forward a request: [%s] %q\n", requestID, err.Error())
	}
}

// pollForNewRequests repeatedly reaches out to the proxy server to ask if any pending are available, and then
// processes any newly-seen ones.
func pollForNewRequests(client *http.Client, hostProxy http.Handler, backendID string) {
	previouslySeenRequests := lru.New(requestCacheLimit)
	var retryCount uint
	for {
		if requests, err := utils.ListPendingRequests(client, *proxy, backendID, metricHandler); err != nil {
			log.Printf("Failed to read pending requests: %q\n", err.Error())
			time.Sleep(utils.ExponentialBackoffDuration(retryCount))
			retryCount++
		} else {
			retryCount = 0
			for _, requestID := range requests {
				if _, ok := previouslySeenRequests.Get(requestID); !ok {
					previouslySeenRequests.Add(requestID, requestID)
					go processOneRequest(client, hostProxy, backendID, requestID)
				}
			}
		}
	}
}
func validateAWSAccess(AWSConfig *aws.Config) {

	svc := sts.New(session.New(AWSConfig))

	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {

			fmt.Println(AWSConfig.Credentials);
			fmt.Println(aerr.Error())

			log.Fatal(aerr.Error())

		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
			log.Fatal(err.Error())
		}

	}

	fmt.Println(result)

	svc2 := iam.New(session.New(AWSConfig))

	/*input2 := &iam.ListGroupsForUserInput{UserName: &strings.Split(*result.Arn, "/")[1]}

	result2, err := svc2.ListGroupsForUser(input2)
	if err != nil {
		log.Fatal("Got error getting groups for user:")

	}

	fmt.Println(result2)

	for _, group := range result2.Groups {
		if *group.GroupName == "InvProxyBackend"+*backendID {

			return
		}
	}*/
	
	
	var entityTags []*iam.Tag

	if strings.HasPrefix(strings.Split(*result.Arn, ":")[5],"user"){
	
		input2 := &iam.ListUserTagsInput{
			UserName: &strings.Split(*result.Arn, "/")[1],
		}

		result2, err := svc2.ListUserTags(input2)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return

			
		}
		entityTags=result2.Tags
		
	} else {

		input2 := &iam.ListRoleTagsInput{
			RoleName: &strings.Split(*result.Arn, "/")[1],
		}

		result2, err := svc2.ListRoleTags(input2)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return

		}
		entityTags=result2.Tags

	}

	
	fmt.Println("Entity tags")
	fmt.Println(entityTags)

		for _,tag := range entityTags {
			
			if(*tag.Key=="AllowedBackends") {
			accessString:=strings.Split(*tag.Value, ",")
			for i := range accessString {
				
				if accessString[i] == *backendID {
				
					return;
				}
			}
		};
	}	

	log.Fatal("You AWS user doesn't have access to backend " + *backendID)

}

func getHTTPClient(ctx context.Context) (*http.Client, error) {
	var err error

	mTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		
		},
	}

	mTLSConfig.InsecureSkipVerify = true
	tr := &http.Transport{
		
		TLSClientConfig: mTLSConfig,
	}
	client := &http.Client{Transport: tr}

	client.Transport = utils.RoundTripperWithVMIdentityAWS(ctx, client.Transport, *proxy, *disableEC2, AWSConfig)

	client.Jar, err = cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})

	if err != nil {
		return nil, err
	}

	return client, nil

}

func configureServiceDiscovery(nameSpaceId string, serviceName string, AWSConfig aws.Config) {

	serviceID := ""

	u, err := url.Parse(*proxy)
	if err != nil {
		panic(err)
	}

	_, port, _ := net.SplitHostPort(u.Host)

	if len(port) == 0 {
		if u.Scheme == "http" || len(u.Scheme) == 0 {
			port = "80"
		} else {
			port = "443"
		}
	}

	ips, err := net.LookupIP(u.Host)

	//ips, err := net.LookupIP("ec2-54-226-246-252.compute-1.amazonaws.com")

	if err != nil {
		fmt.Println(err)
		fmt.Println("Service discovery registration failed")
		return
	}

	proxyIP := ""

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {

			proxyIP = ipv4.String()
		}
	}
	fmt.Println("Using proxy IPv4: ", proxyIP)

	svc := servicediscovery.New(session.New(&AWSConfig))

	requestId, err := uuid.NewV4()

	input := &servicediscovery.CreateServiceInput{
		CreatorRequestId: aws.String(requestId.String()),
		DnsConfig: &servicediscovery.DnsConfig{
			DnsRecords: []*servicediscovery.DnsRecord{
				{
					TTL:  aws.Int64(60),
					Type: aws.String("A"),
				},
			},
			NamespaceId:   aws.String(nameSpaceId),
			RoutingPolicy: aws.String("MULTIVALUE"),
		},
		Name:        aws.String(serviceName),
		NamespaceId: aws.String(nameSpaceId),
	}

	result, err := svc.CreateService(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case servicediscovery.ErrCodeInvalidInput:
				fmt.Println(servicediscovery.ErrCodeInvalidInput, aerr.Error())
			case servicediscovery.ErrCodeResourceLimitExceeded:
				fmt.Println(servicediscovery.ErrCodeResourceLimitExceeded, aerr.Error())
			case servicediscovery.ErrCodeNamespaceNotFound:
				fmt.Println(servicediscovery.ErrCodeNamespaceNotFound, aerr.Error())
			case servicediscovery.ErrCodeServiceAlreadyExists:

				left := "ServiceId: \""
				right := "\""
				rx := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(left) + `(.*?)` + regexp.QuoteMeta(right))
				matches := rx.FindAllStringSubmatch(aerr.Error(), -1)
				serviceID = matches[0][1]
				fmt.Printf("Service %v already exists in CloudMap under service id %v\n", serviceName, serviceID)
				goto continueProcessing

			case servicediscovery.ErrCodeTooManyTagsException:
				fmt.Println(servicediscovery.ErrCodeTooManyTagsException, aerr.Error())

			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

continueProcessing:

	if serviceID == "" {
		serviceID = *result.Service.Id
	}

	requestId2, err := uuid.NewV4()

	input2 := &servicediscovery.RegisterInstanceInput{
		Attributes: map[string]*string{
			"AWS_INSTANCE_IPV4": aws.String(proxyIP),
			"AWS_INSTANCE_PORT": aws.String(port),
		},
		CreatorRequestId: aws.String(requestId2.String()),
		InstanceId:       aws.String(serviceName + "-" + strings.ReplaceAll(proxyIP, ".", "-") + "-" + port),
		ServiceId:        aws.String(serviceID),
	}

	result2, err := svc.RegisterInstance(input2)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case servicediscovery.ErrCodeDuplicateRequest:
				fmt.Println(servicediscovery.ErrCodeDuplicateRequest, aerr.Error())
			case servicediscovery.ErrCodeInvalidInput:
				fmt.Println(servicediscovery.ErrCodeInvalidInput, aerr.Error())
			case servicediscovery.ErrCodeResourceInUse:
				fmt.Println(servicediscovery.ErrCodeResourceInUse, aerr.Error())
			case servicediscovery.ErrCodeResourceLimitExceeded:
				fmt.Println(servicediscovery.ErrCodeResourceLimitExceeded, aerr.Error())
			case servicediscovery.ErrCodeServiceNotFound:
				fmt.Println(servicediscovery.ErrCodeServiceNotFound, aerr.Error())

			default:
				fmt.Println(aerr.Error())
			}
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
			fmt.Println("Service registration failed")
		}
		return
	}
	fmt.Println("Successfully registered service in CloudMap")
	fmt.Println(result2)

}

// waitForHealthy runs health checks against the backend and returns
// the first time it sees a healthy check.
func waitForHealthy() {
	if *healthCheckFreq <= 0 {
		return
	}
	if healthCheck() == nil {
		return
	}
	ticker := time.NewTicker(time.Duration(*healthCheckFreq) * time.Second)
	for range ticker.C {
		if healthCheck() == nil {
			ticker.Stop()
			return
		}
	}
}

// runHealthChecks runs health checks against the backend and shuts down
// the proxy if the backend is unhealthy.
func runHealthChecks() {
	if *healthCheckFreq <= 0 {
		return
	}
	if *healthCheckUnhealthy < 1 {
		*healthCheckUnhealthy = 1
	}
	// Always start in the unhealthy state, but only require a single positive
	// health check to become healthy for the first time, and do the first check
	// immediately.
	ticker := time.NewTicker(time.Duration(*healthCheckFreq) * time.Second)
	badHealthChecks := 0
	for range ticker.C {
		if healthCheck() != nil {
			badHealthChecks++
		} else {
			badHealthChecks = 0
		}
		if badHealthChecks >= *healthCheckUnhealthy {
			ticker.Stop()
			log.Fatal("Too many unhealthy checks")
		}
	}
}

// runAdapter sets up the HTTP client for the agent to use (including OAuth credentials),
// and then does the actual work of forwarding requests and responses.
func runAdapter(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//client, err := getGoogleClient(ctx)

	client, err := getHTTPClient(ctx)
	if err != nil {
		return err
	}
	client.Timeout = *proxyTimeout

	hostProxy, err := hostProxy(ctx, *host, *shimPath, *shimWebsockets)
	if err != nil {
		return err
	}
	pollForNewRequests(client, hostProxy, *backendID)
	return nil
}

func main() {
	flag.Parse()
	ctx := context.Background()

	if *proxy == "" {
		log.Fatal("You must specify the address of the proxy")
	}
	if *backendID == "" {
		log.Fatal("You must specify a backend ID")
	}
	if !strings.HasPrefix(*healthCheckPath, "/") {
		*healthCheckPath = "/" + *healthCheckPath
	}
	if *sessionCookieName != "" {
		sessionLRU = sessions.NewCache(*sessionCookieName, *sessionCookieTimeout, *sessionCookieCacheLimit, *disableSSLForTest)
	}

	//AWSConfig := aws.NewConfig().WithRegion(*region).WithCredentials(credentials.NewStaticCredentials(*awsaccesskey, *awssecret, ""))
	
	if len(*awsaccesskey)>0 && len(*awssecret)>0 && len(*region)>0 {
		AWSConfig = aws.Config{
			Region:           aws.String(*region),
			Credentials:      credentials.NewStaticCredentials(*awsaccesskey, *awssecret, ""),
		}
	} else if len(*region)>0 {

		AWSConfig = *aws.NewConfig().WithRegion(*region)

	}	else 	{

		AWSConfig = *aws.NewConfig()

	}

	validateAWSAccess(&AWSConfig)

	mh, err := metrics.NewMetricHandler(ctx, *namespace, *backendID, AWSConfig)
	metricHandler = mh
	if err != nil {
		log.Printf("Unable to create metric handler: %v", err)
	}

	waitForHealthy()
	go runHealthChecks()

	if len(*SDNamespace) > 0 && len(*SDService) > 0 {
		configureServiceDiscovery(*SDNamespace, *SDService, AWSConfig)
	}
	if err := runAdapter(ctx); err != nil {
		log.Fatal(err.Error())
	}

}
