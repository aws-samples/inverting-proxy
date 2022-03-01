/*
Copyright 2021 Google Inc. All rights reserved.
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

package metrics

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

const (
	samplePeriod = 60 * time.Second
)

var codeCount map[string]int64

// MetricHandler handles metrics collections/writes to cloud monarch
type MetricHandler struct {
	mu        sync.Mutex
	namespace string
	backendID string
	ctx       context.Context
	client    cloudwatch.CloudWatch
}

// NewMetricHandler instantiates a metric client for the purpose of writing metrics to cloud monarch
func NewMetricHandler(ctx context.Context, namespace string, backend string, AWSConfig aws.Config) (*MetricHandler, error) {

	if namespace == "" {
		log.Printf("Skipping metric handler initialization due to empty arguments.")
		return nil, nil
	}
	log.Printf("NewMetricHandler|instantiating metric handler")
	/*client, err := monitoring.NewMetricClient(
		ctx,
		apioption.WithEndpoint(endpoint),
	)*/

	client := cloudwatch.New(session.New(&AWSConfig))

	handler, err := newMetricHandlerHelper(ctx, namespace, backend, *client)

	if err != nil {
		return nil, err
	}

	go func() {
		log.Printf("NewMetricHandler|success metric handler ready")
		ticker := time.NewTicker(samplePeriod)
		defer ticker.Stop()
		for {
			select {
			case <-handler.ctx.Done():
				return
			case <-ticker.C:
				handler.emitResponseCodeMetric()
				handler.mu.Lock()
				codeCount = make(map[string]int64)
				handler.mu.Unlock()
			}
		}
	}()

	return handler, nil
}

func newMetricHandlerHelper(ctx context.Context, namespace string, backend string, client cloudwatch.CloudWatch) (*MetricHandler, error) {

	if namespace == "" {
		err := fmt.Errorf("Failed to create metric handler: missing namespace")
		return nil, err
	}

	codeCount = make(map[string]int64)

	return &MetricHandler{
		namespace: namespace,
		backendID: backend,
		ctx:       ctx,
		client:    client,
	}, nil
}

// GetResponseCountMetricType constructs and returns a string representing the response_count metric type
func (h *MetricHandler) GetResponseCountMetricType() string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("%s/instance/proxy_agent/response_count", h.namespace)
}

// WriteResponseCodeMetric will record observed response codes and emitResponseCodeMetric writes to cloud monarch
func (h *MetricHandler) WriteResponseCodeMetric(statusCode int) error {
	if h == nil {
		return nil
	}
	responseCode := fmt.Sprintf("%v", statusCode)

	log.Printf("Updated metric code: %d", statusCode)

	// Update response code count for the current sample period
	h.mu.Lock()
	codeCount[responseCode]++
	h.mu.Unlock()

	return nil
}

// emitResponseCodeMetric emits observed response codes to cloud monarch once sample period is over
func (h *MetricHandler) emitResponseCodeMetric() {
	log.Printf("WriteResponseCodeMetric|attempting to write metrics at time: %v\n", time.Now())

	for responseCode, count := range codeCount {

		log.Printf("got %v occurances of %s response code\n", count, responseCode)

		_, err := h.client.PutMetricData(&cloudwatch.PutMetricDataInput{
			Namespace: aws.String(h.namespace),
			MetricData: []*cloudwatch.MetricDatum{
				&cloudwatch.MetricDatum{
					MetricName: aws.String("ResponseCount"),
					Unit:       aws.String("Count"),
					Value:      aws.Float64(float64(count)),
					Dimensions: []*cloudwatch.Dimension{
						&cloudwatch.Dimension{
							Name:  aws.String("ResponseCode"),
							Value: aws.String(fmt.Sprintf("%sXX", responseCode[0:1])),
						},
						&cloudwatch.Dimension{
							Name:  aws.String("BackendID"),
							Value: aws.String(h.backendID),
						},
					},
				},
			}})

		if err != nil {
			fmt.Println("Error adding metrics:", err.Error())
			return
		}

	}

}
