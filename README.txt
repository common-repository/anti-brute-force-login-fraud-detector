=== Anti-Brute Force, Login Fraud Detector Wordpress plugin ===
Contributors: aispera31
Tags: security, Brute Force, brute force protection, limit login, login protection, login security, Anti-Brute Force
Requires at least: 5.7
Tested up to: 6.3.2
Requires PHP: 5.6
License:           GNU General Public License v2 or later
License URI:       https://www.gnu.org/licenses/gpl-2.0.html
Stable tag: 1.0.3  

== Description ==

Anti-Brute Force, Login Fraud Detector Wordpress plugin is a security plugin that detects and blocks malicious IP addresses attempting to log into Wordpress sites with real-time intelligence data from Criminal IP.
Hackers attempting brute-force attacks on WordPress sites do not use normal IP addresses. Rather, they use VPN, Proxy, Tor, Hosting IP, etc. to avoid tracking. Criminal IP is an IP address-based intelligence search engine platform that scans worldwide IP addresses daily and collects such malicious information.
The number of detectable login attempts varies depending on the plan being used by the connected Criminal IP account. Users of the Free membership plan can use up to 500 login IP detections per month for free.


= Block Login IP Address Options =

VPN IP - When attempting to log in using a VPN
Tor IP - When attempting to log in from a Tor browser
Proxy IP - When attempting to log in using Proxy
Hosting IP - When attempting to log in from the IP address of a hosting server

= Additional Features =

Whitelist: Specific IP addresses can be added to the whitelist to allow login.
Login Wait Time: Users who are eventually restricted from logging in can try again after the set login wait time.
Blocked IP List: Allows you to view a list of all IP addresses subject to login restrictions. The items that may be seen are as follows.
IP address
Geographic Information (Country)
Reason for Login Restriction (Tor/VPN/Proxy/Hosting)
Detected Date and Time

= Installation =

Installing the Criminal IP Anti-Brute Force, Login Fraud Detector plug-in is very simple.
1. Go to the 'Plugin' menu on the WordPress dashboard.
2. Search 'Criminal IP' or 'Criminal IP Brute Force' in the search window.
3. Click the 'Install and activate' button.
4. When the plugin is activated, an icon with the Criminal IP logo will be displayed on the WordPress dashboard sidebar. Click the icon to go to the dashboard and click the 'Issue API Key' button to go to Criminal IP.
5. Create a Criminal IP account, log in, and create an API key in My Page.
6. Copy and paste the issued API key into the 'Criminal IP API key' input column on the plugin settings tab.
7. On the Settings tab, set the login limit target and login wait time. Click 'Save Changes' to finish setting up the plugin.
Please report any new features or bugs of the plugin through Criminal IP's Customer Support. You can also contact support@aispera.com.
  

== Screenshots ==

1. This is the general settings page for the Criminal IP FDS plugin.
2. This is a list of detected IP addresses based on the restriction options that have been set.
3. On the general settings page, you can activate the plugin and select options for preventing indiscriminate brute-force attacks.
4. On the statistics page, you can view login detection statistics and API usage statistics.
5. This is the screen displayed to users who have been restricted from accessing the website by the Criminal IP FDS plugin.

== Frequently Asked Questions ==
= How to deactivate the plugin if it does not allow me to login due to an error? =
If there is an error or a bug, and you are locked out of the site by this plugin, you can simply delete or rename the plugin folder /wp-content/plugins/wp-criminalip/ using FTP or the file manager of your hosting.

== Upgrade Notice == 

= 1.0.0 =
Upgrade notification  



== Changelog ==
 
= 1.0.0 =
* Initial release to WordPress. 

= 1.0.1 =
* Translation Additions 

= 1.0.2 =
* Database Table Statement modify  