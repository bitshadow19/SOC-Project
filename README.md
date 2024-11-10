# 30-Day MyDFIR SOC Analyst Challenge

## Objective

To develop practical skills in deploying, managing, and securing server environments by setting up and operating an Elasticsearch & Kibana logging solution, ingesting and analyzing logs, and creating custom dashboards and alerts for real-time monitoring. Additionally, gain experience in identifying and responding to security threats, such as brute force and command & control attacks, by configuring a command & control server for controlled testing. Integrate a ticketing system to manage and track alerts and incidents effectively, fostering a hands-on approach to incident response and threat detection in a hybrid server environment


### Skills Learned

- How to spin up your own Elasticsearch & Kibana instance
- Spinning up a Windows & Linux Server
- Ingesting logs into your Elasticsearch instance
- Creating alerts & dashboards
- Learning about brute force attacks & command & control techniques
- Spinning up your own command & control server
- Configuring and integrating your own ticketing system


## Steps
1st Day: Logical Diagram
    This is the start of the 30 day SOC Challenge and the activity is to create a high level topology of the design that I will use. The following are the details of present in the topology
	 1. Servers:
	     a. Elk & Kibana
		 b. Windows Server with RDP enabled
		 c. Ubuntu Server with SSH enabled
		 d. Fleet Server
		 e. Ticket Server
		 f. C2 Server Mythic
	
	 2. Laptops:
	     a. For SOC Analyst
		 b. For Attacker
		 
	 3. Cloud Gateway
	
	 4. Internet Gateway
	
	In the topology, interconnections are also present and in details
	
  
  2nd Day: ELK Stack Introduction
    In this part, I go deep dive with the ELK Tool and this is what I learned about:
	 
     ELK is an acronym for Elasticsearch, Logstash, and Kibana, which are three open-source tools commonly used together for log management and data analysis.
 
      Elasticsearch: A distributed search and analytics engine that stores and indexes data, making it easily searchable. It’s known for its speed and scalability.      

      Logstash: A server-side data processing pipeline that ingests data from various sources, transforms it, and sends it to a "stash" like Elasticsearch. It is used to collect, parse, and enrich logs and other data.

      Kibana: A data visualization tool that works on top of Elasticsearch. It allows users to explore and visualize data stored in Elasticsearch using interactive dashboards and charts.

     Together, ELK is often used in security operations, IT monitoring, and other use cases where analyzing large volumes of log data is important. It's popular in building centralized logging solutions for searching, monitoring, and analyzing log data in real-time.

