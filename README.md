Using a Python virtual environment to run the script is strongly recommended.

# traceroute
**This script has two functions:**
1. Perform a traceroute to the destinations, then save result to local file and send them to RabbitMQ.
2. Check the local files and automatically delete files that are older than the number of days you set.


# config.json
The "config.json" file will be generated automatically by the script with default settings if it does not exist. The default settings are shown below:  
{  
&emsp;"numberOfDaysToRetainLogs": "30",  
&emsp;"frequencyOfCheckingTraceRouteInMinutes": "1440",  
&emsp;"maximum_msg_in_rmq": "10"  
}  

**numberOfDaysToRetainLogs:**
    _Set how long you want the local files that store the traceroute results to be kept._

**frequencyOfCheckingTraceRouteInMinutes:**
    _Time interval between two traceroutes._

**maximum_msg_in_rmq:**
    _Set the maximum number of messages allowed in the RabbitMQ queue._


# destinationHostnames.json
"destinationHostnames.json" is a file that sets traceroute destinations and related parameters.  
It will also be generated automatically by the script with default settings if it does not exist.  
The default settings are as follows. Before running the script, please adjust the parameters according to your requirements. Also you can add more destinations in this file.  

[  
&emsp;{  
&emsp;&emsp;"destination": "bql-sha-association01.asia.apple.com",  
&emsp;&emsp;"protocols": ["icmp", "udp"],  
&emsp;&emsp;"tcp_port": "80",  
&emsp;&emsp;"udp_port": "33434",  
&emsp;&emsp;"maximum_hop": "30"  
&emsp;&emsp;},  
&emsp;{  
&emsp;&emsp;"destination": "bql-sha-ocvi01.asia.apple.com",  
&emsp;&emsp;"protocols": ["icmp", "udp", "tcp"],  
&emsp;&emsp;"tcp_port": "80",  
&emsp;&emsp;"udp_port": "33434",  
&emsp;&emsp;"maximum_hop": "30"  
&emsp;&emsp;}  
]


**destination:**
&emsp;_The hostname or IP address of the target you want to traceroute to._

**protocols:**
&emsp;_Only 3 protocols are allowed. TCP, UDP and ICMP. You can set multiple protocols._

**tcp_port:**
&emsp;_Specify the port when using TCP._

**udp_port:**
&emsp;_Specify the port when using UDP._

**maximum_hop:**
&emsp;_Refers to the maximum number of routers(or network devices) that a packet can traverse before it is either discarded or considered undeliverable._
