# Inverting Application Proxy
This repository contains source code for AWS Inverting Proxy blog on using inverting proxy pattern for multi-point cloud connectivity.

The proxy is based on the original [Inverting Proxy](https://github.com/google/inverting-proxy) project by Omar Jarjur and others modified to run on AWS and integrate with AWS specific security and observability services.

## Deploying and running the solution.

The solution includes a simple Node.js  server application for demonstration purposes. The walkthrough below will use it as an example server-side application to simulate on-premises connectivity with inverting proxy. We will rely on a restrictive Security Group to simulate behind-the-firewall on-premises configuration.

Steps:

1.	Create a “backend” Amazon EC2 server using Linux 2, free-tier AMI. Ensure that Port 443 (inbound port for  sample server application) is blocked from external access via appropriate security group.

2.	SSH into target server and run updates:

    sudo yum update -y

3.	Install development tools and dependencies:

    sudo yum groupinstall "Development Tools"

4.	Install go:

  	sudo yum install golang -y

5.	Follow [these](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-up-node-on-ec2-instance.html) instructions to install node.js

6.	Install git by running: 

    sudo yum install git -y

7.	Clone the inverting proxy GitHub repository to the “backend” EC2 instance

8.	Build the application by running:

    export GOPATH=/home/ec2-user/inverting-proxy/bin
    make

9.	From /simple-server folder, run the sample appTLS application in the background (see instructions below). Note: to enable SSL you will need to generate encryption key and certificate files (server.crt and server.key) and place them in simple-server folder. 

    node appTLS &
    Example app listening at https://localhost:443

    Confirm that the application is running by using ps -ef | grep node:

    ec2-user  1700 30669  0 19:45 pts/0    00:00:00 node appTLS
    ec2-user  1708 30669  0 19:45 pts/0    00:00:00 grep --color=auto node

10.	For backend Amazon EC2 server, navigate to Amazon EC2 security settings and create an IAM role for the instance. Keep default permissions and add “AllowedBackends” tag with the backend ID as a tag value (the backend ID can be any string that matches the backend ID parameter in Step 8).

11.	Create a proxy Amazon EC2 server using Linux AMI in a public subnet and connect by using SSH in an Amazon EC2 once online. Copy the contents of the bin folder from the agent EC2 or clone the repository and follow build instructions above (steps 2-8).

Note: the agent will be establishing outbound connectivity to the proxy; open the appropriate port (443) in the proxy Amazon EC2 security group. The proxy server needs to be accessible by the backend Amazon EC2 and your client workstation, as you will use your local browser to test the application. 

12.	To enable TLS encryption on incoming connections to proxy, you will need to generate and upload the certificate and private key (server.crt and server.key) to the bin folder of the proxy deployment.  

13.	Navigate to /bin folder of the inverting proxy and start the proxy by running:

    sudo ./inverting-proxy –port 443 -tls
    2021/12/19 19:56:46 Listening on [::]:443

14.	Use the SSH to connect into the backend Amazon EC2 server and configure the inverting proxy agent. Navigate to /bin folder in the cloned repository and run the command below, replacing uppercase strings with the appropriate values. Note: the required trailing slash after the proxy DNS URL.

    ./ proxy-forwarding-agent -proxy https://YOUR_PROXYSERVER_PUBLIC_DNS/ -backend SampleBackend-host localhost:443 -scheme https

15.	Use your local browser to navigate to proxy server public DNS name (https://YOUR_PROXYSERVER_PUBLIC_DNS). You should see the following response from your sample backend application: 

    Hello World!

