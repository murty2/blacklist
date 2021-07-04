# IPv4 Blacklist for iptables

## Currently for iptables only. (nft version coming soon)

### Just want to apply my IP blacklist, without creating your own?

If you are impatient or just want to apply my IPv4 blacklist on your webservers or mail servers, then just run:

blacklist-apply.sh https://lunar.murty.net/ipset.txt

### Detailed Instructions

*blacklist-gen.sh*

Change the following line to suit your website's docroot

RESTORE=/path/to/your-docroot/ipset.txt

Then run the script. It will generate the ipset blacklist file

*blacklist-apply.sh*

Run on your webservers & mail servers: /root/blacklist-apply.sh https://your-website.com/ipset.txt
