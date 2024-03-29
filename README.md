Security SSID ABI (SSID WiFi Listener)
==========

Using a monitor-mode 2.4Ghz receiver, this Django app displays data that is catalogued from passively sniffing on SSID probes, ARPs, and MDNS (Bonjour) packets that are being broadcast by nearby wireless devices.

Some devices transmit ARPs, which sometimes contain MAC addresses (BSSIDs) of previously joined WiFi networks, as described in [[1]][ars].  This system captures these ARPs and displays them.

Components
----------

2 major components and further python modules:

* main.py uses [Scapy](http://www.secdev.org/projects/scapy/) to extract data from a live capture (via airmon-ng) or pcap file, and inserts this data into 2 databases: Client Summary and Access Point summary data is loaded into a SQLite or Postgres DB (managed by Django), which is the data that is displayed in the Django web app.

 Beyond the summary Client Data, all 802.11 (aka Dot11) packet summaries are loaded into a second database: InfluxDB 1.8.

* A Django web app provides an interface to view and analyse the data.
This includes views of:

1. All detected devices and the SSIDs / BSSIDs each has probed
1. A view by network
1. A view showing a breakdown of the most popular device manufacturers, based on client MAC address Ethernet OUIs

* ./location_utils/wloc.py provides a _QueryBSSID()_ function which looks up a given BSSID (AP MAC address) on Apple's WiFi location service. It will return the coordinates of the MAC queried for and usually an additional 400 nearby BSSIDs and their coordinates.

* ./location_utils/wigle_lib.py provides a _getLocation()_ function for querying a given SSID on the wigle.net database and returns GPS coordinates. Note: It must be configured with a valid username and password set in the settings.py file. Please respect the wigle.net ToS in using this module. This project-specific library has been created to work with the new Wigle API (V2: https://api.wigle.net/swagger#/Network_search_and_information_tools). Big thanks to the Wigle team for their great support and allowing this project to use their data.

*** Instructions
------------
Install Anaconda 3 for Linux: https://www.anaconda.com/products/individual#linux

```
git clone git@github.com:GISDev01/security-ssid-abi.git
cd security-ssid-abi
conda env create -f environment.yml
source activate securityssidabi38

# Initialize the initial Django DB
./manage.py migrate --run-syncdb 
./manage.py createsuperuser
# Create creds to log in to the /admin Web GUI endpoint)

# Start the web interface by running 
# (change 127.0.0.1 to any IP for the Django web server to listen on)
./manage.py runserver 127.0.0.1:8000

```

# To sniff traffic
```
sudo apt install aircrack-ng -y && sudo apt install git -y && sudo apt install libpq-dev
# We can only run the sniffer as root, because it opens a raw socket (via scapy sniff)
sudo -i
```

Bring up a wifi interface in monitor mode (usually mon0) so that airodump-ng shows traffic.

`sudo airmon-ng check kill`

Note: check what the connected wireless NIC device is named using iwconfig

`iwconfig`

Make sure the USB wireless NIC, such as an Alfa AWUS036 is passed-through to the VM
Example value is: wlx00c0ca4f55b9 (or it could be something like wlan0)

`sudo airmon-ng start wlx00c0ca4f55b9`

- Sometimes the OS and Wireless card like to act up and display a message like: "SIOCSIFFLAGS: Operation not possible due to RF-kill". In that case, this can help:
`sudo rfkill unblock wifi; sudo rfkill unblock all`

4. Optional (set to false by default in setting.py). Get InfluxDB up and running, and update the .\security_ssid\settings.py with the correct IP or hostname of the InfluxDB box.

Note: Fastest way to get it up and running for development is with Docker:

`docker run -p 8086:8086 influxdb:1.8.0`

5. Start live sniffing with:

 `./run.sh -i mon0`

 (Note: the -i param here is to identify the interface name that airmon-ng is monitoring packets with, default value is actually mon0)


Optional: To solicit ARPs from iOS devices, set up an access point with DHCP disabled (e.g. using airbase-ng) and configure your sniffing interface to the same channel.
Once associated, iOS devices will send up to three ARPs destined for the MAC address of the DHCP server on previously joined networks. On typical home WiFi routers, the DHCP server MAC address is the same as the WiFi interface MAC address, which can be used for accurate geolocation.

Optional: For debugging code locally, a .pcap (in this case, .cap) file can be generated with (as root or with sudo):

`airodump-ng -w sample-data --output-format pcap mon0`

Then you can run with (assuming sample-data.cap is in the root of this repo):

`./run.sh -r sample-data.cap`

To run Postgres in Docker for testing, as an alternative to sqlite
```
docker run -d -p 5432:5432 --name postgres95 -e POSTGRES_PASSWORD=postgres postgres:9.5
```
If needed, get in to the box with:

`docker exec -it postgres95 bash`

`psql -U postgres`


Dependencies
------------------------------------------------------------------------------------------------------------
See requirements.txt for python modules and versions required.
Externally, this application writes out to an InfluxDB data store (in addition to the local Django DB (sqlite)).

This repo has been recently developed on a Ubuntu 16.04 (64-bit) VM with Python 3.8, Django 4.x and Scapy 2.4.x. 
The web interface code has been updated and tested with Django running on Mac OS X Sierra with Python 3.8.

Network sniffing via airmon-ng has been tested on a Ubuntu 16.04 VM and Raspian (RasPi 3).

Credits
------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------
This repo was originally written by @hubert3 / hubert(at)pentest.com. Presented at Blackhat USA July 2012, the original code published on Github 2012-08-31.
The implementation of wloc.py is based on work by François-Xavier Aguessy and Côme Demoustier [[2]][paper].
Mark Wuergler of Immunity, Inc. provided helpful information through mailing list posts and Twitter replies.
Includes Bluff JS chart library by James Coglan.
1. http://arstechnica.com/apple/2012/03/anatomy-of-an-iphone-leak/
2. http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/
[ars]: http://arstechnica.com/apple/2012/03/anatomy-of-an-iphone-leak/
[paper]: http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/

(gisdev01) Starting in mid-2017 and then again in 2020, several updates and upgrades have been completed, including addition of InfluxDB functionality, summary functionality, Raspberry Pi support, and several front-end updates.



```
conda install Django
conda install matplotlib
conda install -c conda-forge influxdb
conda install -c conda-forge netaddr
conda install -c conda-forge google-api-core

# Not available in any conda channels
pip install django-picklefield

conda env export > environment.yml
conda env create -f environment.yml




```