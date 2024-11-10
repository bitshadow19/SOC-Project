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

30 Day SOC Challenge
 
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
	
	
  3rd Day: Elasticsearch Setup
    In this day, I created an account in Vultr.com - a cloud infrastructure provider that offers a variety of cloud computing services, including virtual private servers (VPS), bare metal servers, block storage, and more. It’s known for providing scalable, high-performance infrastructure with a global presence, offering data centers in multiple locations around the world.
	Then I created a new VM instance then I select Ubuntu Server version 22.04. This is where I will run the Elasticsearch. After that, I updated all the apps in the Ubuntu Server and then download the Elasticsearch via wget. After that I installed the Elasticsearch then tweak some configuration on VM Firewall so that it will not be available in the whole internet.
	
 
  4th Day: Kibana Setup
    On this day, Kibana is next to configure. Kibana is a powerful open-source data visualization and analytics tool that works on top of Elasticsearch, which is part of the Elastic Stack (formerly known as the ELK Stack: Elasticsearch, Logstash, Kibana). Kibana is primarily used to visualize large amounts of data and logs, making it useful for monitoring, reporting, and dashboard creation
	Just like the Elasticsearch, the Kibana sofware is downloaded via wget. After installation, I must integrate the Kibana to Elasticsearch by creating a token from Elasticsearch then put it to Kibana. After the creation of token and accessing Kibana via a public IP, I have an issue which is I can't access the Kibana, so I make another firewall rules to allow my IP and allow the port 5601. After that it works well. I feel information overload from this but it is fun afterall.
	
	
  5th Day: Windows Server 20222 Intallation
    On this day, I configure the Windows Server 2022 to our Vultr Cloud. The installation is very easy and straighforward. This are the basic settings: CPU is 2 vcpu, 2gb Ram, 55gb storage, no autobackup and no IPv6. Also this Server has no VPC 2.0 because if this server is compromise, the other will also be compromise. After finishing this, I also update the topology design and the Server is outside the VCP 2.0. So that is how easy this activity today.


  6th Day: Elastic Agent and Fleet Server Introduction
    On this day, I learned introductin about Elastic Agent and Fleet Server.
	
	Elastic Agent - is like a heavy forwarder on Splunk. it is a unified, lightweight agent developed by Elastic that collects data from various systems and forwards it to the Elastic Stack for centralized monitoring, analysis, and security operations. It simplifies the process of managing multiple data shippers and beats (like Filebeat, Metricbeat, etc.) by consolidating them into a single, easily deployable agent. This agent can be deployed as standalone or fleet managed. Alternative to Elastic Agent, you can used what is called Beats
	
	Fleet Server - is a component within the Elastic Stack used to centrally manage and coordinate Elastic Agents. It acts as the communication hub for Elastic Agents deployed across different systems and environments, allowing administrators to manage, configure, and monitor agents at scale via Fleet, which is the management interface for Elastic Agents in Kibana.
	
	On this 30 day challenge, I will used the Elastic Agent and Fleet Server to managed the agents.
	
  7th Day: Elastic Agent and Fleet Server Setup
	On this day, I created a new server which is the Fleet Server. The settings is just like the Windows Server with basic resources. But regarding the network, It is under the VPC 2.0 and not like the Windows Server 2022. After installation, it must be integrated to the ELK Stack Sever I created a few days ago. To do this is by setup a new Fleet Server from the menu un ELK then configure the IP Address, Firewall Policy including the port number (9200) and other settings. Then it should connect to our ELK Server.
	Next is pushing an agent to our Windows Sever 2022. In our Fleet Server, I enrolled an elastic agent, then select Windows since our Server is a Windows based. After enrolling, I copied the srcipt that will be used. I login to the Windows Server and open the Power Shell and paste the script. Then it works. I now have agent installed in Windows Server 2022
	
  8th Day: What is Sysmon
    This day is the introduction of Sysmon.System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.

	Sysmon includes the following capabilities:

     Logs process creation with full command line for both current and parent processes.
     Records the hash of process image files using SHA1 (the default), MD5, SHA256 or IMPHASH.
	 Multiple hashes can be used at the same time.
	 Includes a process GUID in process create events to allow for correlation of events even when Windows reuses process IDs.
	 Includes a session GUID in each event to allow correlation of events on same logon session.
	 Logs loading of drivers or DLLs with their signatures and hashes.
	 Logs opens for raw read access of disks and volumes.
	 Optionally logs network connections, including each connection’s source process, IP addresses, port numbers, hostnames and port names.
	 Detects changes in file creation time to understand when a file was really created. Modification of file create timestamps is a technique commonly used by malware to cover its tracks.
	 Automatically reload configuration if changed in the registry.
	 Rule filtering to include or exclude certain events dynamically.
	 Generates events from early in the boot process to capture activity made by even sophisticated kernel-mode malware.
	
  9th Day: Sysmon Installation
    On this day, I am going to install Sysmon on the Windows Server 2022 and the following are the steps I have taken:
	 1. Download the Sysmon from learn.microsoft.com and the latest version upon this writing is 15.15
	 2. Extract the downloaded file
	 3. Download the configuration file - OLAF at github page
	 4. Select the 'sysmonconfig.xml', then select 'raw' and then right click and choose save as and save on sysmon directory
	 5. Open the powershell with admin priviledge then go to the directory of sysmon
	 6. Type .\sysmon.exe -i sysmonconfig.xml then hit enter then hit 'I accept'
	 7. Wait for the installation to finish
	 
	That is how easy to install Sysmon and if you go to the event viewer, you can see a couple of events.
	
  10th Day: Ingesting Sysmon and Windows Defender Logs into Elastic Search
    On this day, I configure Sysmon to forward logs to Elastic Search and the following are the steps I have done:
	  
	  Navigate to the Elastic GUI and locate the “Add integration” button.

	  In the search bar, type “Custom Windows Event logs” and select it.

	  Click “Add custom Windows event logs” on the next screen.	

	  Provide a name for the integration (e.g., “Sysmon Logs”) and a description (e.g., “Collect logs from Sysmon”).

	  For the channel name, you’ll need to reference your Windows server:

	  Open Event Viewer on your Windows server
	    Navigate to Application and Services Logs > Microsoft > Windows > Sysmon > Operational
	    Right-click and select Properties
	    Copy the full name provided — this is your channel name
	    Paste this into the Elastic GUI
	
	  When prompted, select your existing Windows Server as the host for these integrations.
	  
	 
	I also repeat the above steps in Windows Defender 
      
	  Create a new integration named “Windows Defender Logs” with an appropriate description
	  
	  Locate the Windows Defender > Operational log in Event Viewer
	  
	  Copy the full name from Properties and paste into Elastic	
	
	So that is how easy to ingest Sysmon and Windows Defender Logs into Elastic Search
	


  11th Day: Introduction to Brute Force Attack
    On this day, I study  about Brute Force Attack. It is a trial-and-error method used to decode sensitive data. The most common applications for brute force attacks are cracking passwords and cracking encryption keys (keep reading to learn more about encryption keys). Other common targets for brute force attacks are API keys and SSH logins. Brute force password attacks are often carried out by scripts or bots that target a website's login page.
	What differentiates brute force attacks from other cracking methods is that brute force attacks don’t employ an intellectual strategy; they simply try using different combinations of characters until the correct combination is found. This is kind of like a thief trying to break into a combo safe by attempting every possible combination of numbers until the safe opens.
	

  12th Day: Installation of Ubuntu Server version 24.02
    On this day, I am going to install Ubuntu VM into our Vultr Cloud Provider. The process is like on my previous installation of Ubuntu Server. The specifications are not high. The given name is MyDFIR-Linux-regireyes19. Backup and IPv6 are disabled and no VPC also. 
    
	
  13th Day: Installation of Agent in Ubuntu Server	
	For the agent installation, just like also the previous installation, create first the agent policy and give it a name. After that click on the create agent and select the policy that I created. Then copy the installation script then SSH to the Ubuntu VM then paste what I copied. Then I wait and that's it. The installation of agent is done

  14th Day: Creating alerts and dashboard in Kibana - SSH 
    On this day, It is time to create an Alert and Dashboard in our Kibana. First thing is that go to humberger icon in our Elastic and select "Discover" Select the agent.name and choose our Linux Agent. Approximately it has 27000+ alerts within 30 days. To filter this and to make a custom alerts, we need the information pertaining to the failed authentication, users, source ip and country. For the failed authentication, I used the field 'system.auth.ssh.event'. For the users, it is 'user.name' field. For the source IP, I used the 'user.ip' field and 'source.geo.country_name' for the country. Then save it. Next is to create an alert by clicking the Alert tab and choose 'create search threshold. Give it a name for Creating a Rule then you can customize the alert threshold. You can set when this alert be triggered. And that how easy to make an alert in Kibana
	For the creation of the Dashboard. I used the newly created Alert as the basis. First go to the humberger icon then select Dashboard. Then select 'Add Layer' and choose 'Choropleth' because it will be base on the Country Field. Select the Boundaries source from 'Elastic Maps Service' then in the Statistics Source select 'source.geo.country-id. Then here you go, the creation of Dashboard is done.
  

  15th Day: Remote Desktop Protocol Introduction:
    This day, I study about Remote Desktop Protocol. RDP is a proprietary protocol developed by Microsoft that allows a user to connect to and control another computer over a network connection. The advantage of RDP are accessiblity, easy troubleshooting and cost saving. 
	But this advantages has a risk. Attacker can exploit RDP and this will make a way for the attacker to go inside your network. Attackers exploit RDP (Remote Desktop Protocol) in various ways to gain unauthorized access to systems. One of the most common is the Brute-Force Attack. To mitigate RDP attacks, here are some recommendations:
	  1. Disable the protocol
	  2. Used Multi-Factor Authentication
	  3. Used complex password
	  
  16th Day: Creating alerts and dashboard in Kibana - RDP Brute Force
   This day is the continuation (2nd part) of creating alerts and it is for RDP brute force in Kibana. Just like the 1st part we just need to filter the information pertaining the failed authentication, users, user ip and country. The basis of the search is to select the agent for windows and filter the event code 4625. Then follow the steps on what I do on the 1st part
    
	
  17th Day: Creating alerts and dashboard - with maps
    This day is the continuation again of 3rd part of creating alerts and dashboard. So both the RDP and SSH created Alert will be used. First create a map, go to the humberger icon and select Map. Copy the filter alert that I created for RDP and paste it. Then click add layer. The source should be the country. Then do this for the SSH. And That is it.
	
	
  18th Day: Introduction to Command and Control
    This day is the introduction of C2 because this will be our next to build. In the realm of cybersecurity, command and control (C2) takes on a particularly sinister meaning. It refers to the methods and infrastructure that cybercriminals use to communicate with and control compromised systems, often referred to as "bots" or "zombies." C2 serves as the lifeline for attackers, allowing them to send commands, exfiltrate data, and maintain their foothold within a network.

	Understanding C2 is critical for defenders, as disrupting these channels of communication can severely cripple an attacker's ability to operate. C2 mechanisms can vary widely in complexity, from simple scripts and hardcoded IP addresses to sophisticated, multi-layered networks designed to evade detection.
	
 
  19th Day: Creating an Attack Diagram
    This day is to design a diagram in relation with the Command and Control. The diagram or topology shows the Phases of an attack as follows
	  1. Initial Acess
	  2. Discovery
	  3. Defense Evasion
	  4. Execution
	  5. Command and Control
	  6. Exfiltration
	 

	
  Day 20: Mythic Setup Tutorial

Alright, let's get our hands dirty and set up our own attacker infrastructure! Today, we'll walk through setting up a Mythic C2 server on Vultr.com.  First things first, head over to Vultr and spin up a new server instance. I recommend choosing an Ubuntu Server with decent specs—you don't need anything too powerful, but make sure it has enough resources to handle the C2 activity. Once your server is running,  it's time to install Mythic. You can grab the latest version from their GitHub repository and follow their installation instructions.  Don't forget to configure Mythic with your desired settings, like creating user accounts and setting up listeners.  Oh, and one crucial thing:  secure your server! Make sure to configure your firewall to restrict access and use strong SSH keys. We don't want any unwanted visitors poking around our attacker playground!

Day 21:  Mythic Agent Setup

Now that our C2 server is up and running, let's create some agents to deploy on our target systems. Mythic makes this super easy, allowing you to generate payloads for different operating systems like Windows, Linux, and macOS.  Think of these agents as our little spies, ready to infiltrate and execute our commands.  We can deliver them through various methods, like email attachments or even a good old-fashioned USB drive. Once the agent is on the target system, it will connect back to our C2 server, giving us remote control.  From there, we can run commands, steal data, and basically do whatever we want (within the confines of our ethical hacking challenge, of course!).

Day 22: Kibana Alerts for Mythic

We've got our attacker infrastructure ready, but how do we detect this activity from a defender's perspective? That's where our trusty ELK stack comes in!  Mythic agents communicate with the C2 server, generating network traffic that we can analyze.  We'll dive into Kibana and craft some queries to filter out Mythic-related events.  We'll also set up alerts to notify us of any suspicious Mythic activity.  And to top it off, we'll build a fancy Kibana dashboard to visualize these attacks in real-time.  Think of it as our command center for monitoring and responding to these simulated threats.

Day 23: Ticketing Systems in the SOC

Let's take a break from the technical stuff and talk about organization.  In a real-world SOC, things can get hectic with alerts flying in from all directions.  That's where a ticketing system comes in handy.  It helps us keep track of all the security events, assign them to analysts, and ensure that nothing falls through the cracks.  We'll explore the different types of ticketing systems out there and discuss the key features that make them effective for incident response and collaboration within the SOC.

Day 24:  osTicket Setup

Time to get our hands dirty again!  Today, we'll install and configure osTicket, a popular open-source ticketing system.  We'll walk through the entire process, from downloading and installing osTicket to configuring email notifications, setting up departments, and adding our SOC analysts as agents.  We'll even explore some customization options to make osTicket fit seamlessly into our SOC workflow.

Day 25:  osTicket and ELK Integration

Now, let's connect the dots between our ticketing system and our log analysis platform.  Wouldn't it be awesome if Elasticsearch could automatically create tickets in osTicket whenever it detects a critical security event?  Well, that's exactly what we'll do today! We'll configure Elasticsearch alerts to trigger new tickets in osTicket, enriching them with valuable data from our logs.  This integration will streamline our incident response process, allowing us to quickly investigate and respond to threats.

Day 26:  SSH Brute-Force Investigation

Let's put our SOC skills to the test and investigate a simulated SSH brute-force attack.  We'll dive deep into our SSH logs within Kibana, analyze the attack patterns, and pinpoint the attacker's IP address and location.  By correlating different events, we'll piece together the attack timeline and understand the attacker's methods.  Finally, we'll document our findings, draw conclusions, and recommend mitigation strategies to prevent future attacks.

Day 27:  RDP Brute-Force Investigation

Similar to our SSH investigation, today we'll tackle an RDP brute-force attack.  We'll sift through Windows security events, focusing on those related to RDP login attempts.  We'll identify any compromised accounts, analyze suspicious login patterns, and investigate any signs of lateral movement or privilege escalation.  Our goal is to understand the full extent of the attack and contain the damage.

Day 28:  Mythic Agent Investigation

Remember that Mythic C2 infrastructure we set up?  It's time to see it in action from a defender's perspective.  We'll analyze our network traffic logs to detect any signs of Mythic agent activity.  We'll then delve into the agent's command history to understand the attacker's objectives and uncover any data exfiltration attempts.  This investigation will give us valuable insights into how attackers use C2 frameworks to compromise systems and carry out their malicious activities.

Day 29: Elastic Defend Setup

Let's add another layer of security to our SOC by introducing Elastic Defend.  This endpoint security solution provides real-time threat detection and response capabilities.  We'll install and configure Elastic Defend agents on our systems, learn how to monitor endpoint activity, and explore how to respond to security incidents directly on the endpoints.  This will strengthen our defenses and give us greater visibility into what's happening on our systems.

Day 30: Log Troubleshooting

Log analysis isn't always smooth sailing.  Sometimes we encounter challenges like noisy logs, missing data, or even issues with Elasticsearch itself.  On this final day, we'll share some common log analysis challenges and provide troubleshooting tips to overcome them.  We'll also discuss how to use logs to diagnose performance problems and ensure that our ELK stack is running smoothly.

I hope this is more in line with what you were looking for! I've tried to make the descriptions more engaging and conversational, while still providing valuable information for your blog posts.  Let me know if you have any other questions or need further assistance. Good luck with the rest of your challenge!
   
General Tips for Log Troubleshooting:

Start with the basics: Check connections, configurations, and permissions before diving into complex debugging.
Divide and conquer: Isolate the problem by systematically checking different components of your logging pipeline.
Document your findings: Keep detailed notes of your troubleshooting steps and observations.
Don't be afraid to ask for help: The Elasticsearch and Kibana communities are great resources for getting support.   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
