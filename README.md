Security SSID ABI (SSID WiFi Listener)
==========

Using a monitor-mode 2.4Ghz receiver, this Django app displays data that is catalogued from passively sniffing on SSID probes, ARPs, and MDNS (Bonjour) packets that are being broadcast by nearby wireless devices.

Some devices transmit ARPs, which sometimes contain MAC addresses (BSSIDs) of previously joined WiFi networks, as described in [[1]][ars].  This system captures these ARPs and displays them.

Components
----------

2 major components and further python modules:

* main.py uses [Scapy](http://www.secdev.org/projects/scapy/) to extract data from a live capture or pcap file, and inserts it into a database.

* A Django web app provides an interface to view and analyse the data.
This includes views of:

1. All detected devices and the SSIDs / BSSIDs each has probed
1. A view by network
1. A view showing a breakdown of the most popular device manufacturers, based on client MAC address Ethernet OUIs

* ./location_utils/wloc.py provides a _QueryBSSID()_ function which looks up a given BSSID (AP MAC address) on Apple's WiFi location service. It will return the coordinates of the MAC queried for and usually an additional 400 nearby BSSIDs and their coordinates.

* ./location_utils/wigle_lib.py provides a _getLocation()_ function for querying a given SSID on the wigle.net database and returns GPS coordinates. Note: It must be configured with a valid username and password set in the settings.py file. Please respect the wigle.net ToS in using this module. This project-specific library has been created to work with the new Wigle API (V2: https://api.wigle.net/swagger#/Network_search_and_information_tools). Big thanks to the Wigle team for their great support and allowing this project to use their data.

*** Instructions
------------

* To use the web interface:
Prereq: Python 3.7 and pip installed

1. Install or update required Python modules by running

`pip install -r requirements.txt`

2. Initialize an empty sqlite database (for Django) by running

`python manage.py migrate --run-syncdb`

`./manage.py createsuperuser` (Create creds to log in to the /admin endpoint)

3. Start the web interface by running

`./manage.py runserver 127.0.0.1:8000`

(change 127.0.0.1 to any IP that you want the Django web server to listen on)

* To sniff traffic (possible to use a static .pcap file or to use a live monitoring interface)
Preq: airodump-ng (part of aircrack-ng) for live monitoring

1. Install scapy (it is included in the requirements.txt)
2. For a pcap file: Import data from a wifi pcap capture by running

`./run.sh -r <chan11.pcap>`

3. For live capture:

Bring up a wifi interface in monitor mode (usually mon0) so that airodump-ng shows traffic.

Steps to get this running on a Ubuntu 16.04.6 Box
Install Anaconda 3 for Linux: https://www.anaconda.com/products/individual#linux


`sudo apt install aircrack-ng -y && sudo apt install git -y`

`conda create --name securityssidabi37 python=3.7`

`git clone https://github.com/GISDev01/security-ssid-abi.git`

`cd security-ssid-abi`

`source activate securityssidabi37`

`pip install -r requirements.txt`

`sudo airmon-ng check kill`

`iwconfig`

(check what your wireless NIC device is called using iwconfig
(make sure your USB wireless NIC, such as an Alfa AWUS036 is passed-through to the VM)
Example value is something like: wlx00c022ca92321337a (or it could be something like wlan0)

`sudo airmon-ng start wlx00c022ca92321337a`

4. Get InfluxDB up and running, and update the .\security_ssid\settings.py with the correct IP or hostname of the InfluxDB box.
Note: Fastest way to get it up and running for development is with Docker:

* docker run -p 8086:8086 influxdb:1.8.0


5. Start live sniffing with:

 `./run.sh -i mon0`

 (Note: the -i param here is to identify the interface name that airmon-ng is monitoring packets with, default value is actually mon0)


Optional: To solicit ARPs from iOS devices, set up an access point with DHCP disabled (e.g. using airbase-ng) and configure your sniffing interface to the same channel.
Once associated, iOS devices will send up to three ARPs destined for the MAC address of the DHCP server on previously joined networks. On typical home WiFi routers, the DHCP server MAC address is the same as the WiFi interface MAC address, which can be used for accurate geolocation.


Dependencies
------------

See requirements.txt for python modules and versions required.
Externally, this application writes out to an InfluxDB data store.

This repo has been recently developed on a Ubuntu 16.04 (64-bit) VM with Python 3.7, Django 3.x and Scapy 2.4.x.
The web interface code has been updated and tested with Django running on Mac OS X Sierra with Python 3.7.x.

Network sniffing via airmon-ng has been tested on MacOS High Sierra 10.13.3, Windows 10, Ubuntu 16.04, and Raspian (RasPi 3).


Credits
-------
This repo was originally written by @hubert3 / hubert(at)pentest.com. Presented at Blackhat USA July 2012, the original code published on Github 2012-08-31.
The implementation of wloc.py is based on work by François-Xavier Aguessy and Côme Demoustier [[2]][paper].
Mark Wuergler of Immunity, Inc. provided helpful information through mailing list posts and Twitter replies.
Includes Bluff JS chart library by James Coglan.
1. http://arstechnica.com/apple/2012/03/anatomy-of-an-iphone-leak/
2. http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/
[ars]: http://arstechnica.com/apple/2012/03/anatomy-of-an-iphone-leak/
[paper]: http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/

(gisdev01) Starting in mid-2017 through 2020, several updates and upgrades are in progress, including addition of InfluxDB functionality, summary functionality, Raspberry Pi support, and several front-end updates.
