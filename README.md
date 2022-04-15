# Inverting Application Proxy
This repository contains source code for Inverting Proxy in support AWS blog on using inverting proxy pattern for multi-point cloud connectivity.

The proxy is based on the original [Inverting Proxy](https://github.com/google/inverting-proxy) project by Omar Jarjur and others modified to run on AWS and integrate with AWS specific security and observability services.

## Deploying and running the solution.

The solution includes a simple Node.js  server application for demonstration purposes. The walkthrough below will use it as an example server-side application to simulate on-premises connectivity with inverting proxy. We will rely on a restrictive Security Group to simulate behind-the-firewall on-premises configuration.
Steps:

1.	Create a “backend” EC2 server using Amazon Linux 2 free tier AMI and deploy Node.js to it to run a sample server application. You can use public subnet for simplicity but for the purposes of the demo ensure that port 443 (inbound port for our sample server app) is    
    blocked from external access via Security Group.
    
(SSH into target server)

sudo yum update -y

2.	Follow these instructions to install node.js

3.	Clone the Inverting proxy repository to the “backend” instance

4.	From /simple-server folder, run the sample encrypted server application in the background. Note that for SSL-enabled version you would need to generate encryption key and certificate files (server.crt and server.key) and place them in simple-server folder. 

node appTLS &
Example app listening at https://localhost:443

    Confirm that the application is running by using ps -ef | grep node:

ec2-user  1700 30669  0 19:45 pts/0    00:00:00 node appTLS
ec2-user  1708 30669  0 19:45 pts/0    00:00:00 grep --color=auto node

5.	For backend EC2 server, navigate to EC2 security settings and create IAM Role for the instance. Keep default permissions and add “AllowedBackends” tag with the backend ID as a tag value (backend ID can be any string that matches backendID parameter given in step 8 below).

6.	Create a proxy EC2 server using Amazon Linux AMI in a public subnet and SSH into EC2 once available. Clone the Inverting proxy repository. Note that the agent will be establishing outbound connectivity to the proxy, thus you will need to open the appropriate port (443) 
    in proxy EC2 security group. The proxy server will need to be accessible by the backend EC2 and your client workstation as you will be using your local browser to test the app. 

7.	To enable TLS encryption on incoming connections to proxy, you will need to generate and upload certificate and private key (server.crt and server.key) to the bin folder of the proxy deployment.  

8.	From cloned repository, navigate to /bin folder and start proxy by running:

sudo ./inverting-proxy –port 443 -tls
2021/12/19 19:56:46 Listening on [::]:443

9.	SSH back into backend EC2 server and configure the inverting proxy agent. Navigate to /bin folder in cloned repository and run the command below, replacing uppercase strings with the values appropriate to your environment. Note the required trailing slash after the   
    proxy DNS URL.

./ proxy-forwarding-agent -proxy https://YOUR_PROXYSERVER_PUBLIC_DNS / -backend SampleBackend-host localhost:443 -scheme https

10.	Use your local browser to navigate to proxy server public DNS name (https://YOUR_PROXYSERVER_PUBLIC_DNS):
    You should see the following response from your sample backend application forwarded via agent/proxy:

Hello World!

