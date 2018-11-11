# GameStream IPv6 Forwarder
Current versions of GeForce Experience do not listen on IPv6 for connections from GameStream clients by default.

Running this forwarding service on the GameStream host allows Moonlight clients to access it over IPv6. It also automatically configures PCP-compatible IPv6 firewalls to allow GameStream traffic to your PC from the Internet.

This tool can allow Moonlight access to multiple PCs behind a single router if your server and client both have IPv6 connectivity.

# Instructions
1. Download MSI package from the [GitHub Releases](https://github.com/moonlight-stream/GS-IPv6-Forwarder/releases) page.
2. Install the package on your gaming PC. The service will run automatically in the background.
3. Give it a try! Connect via Moonlight using an IPv6 address or host name.

# Troubleshooting
1. Make sure that your router and PC firewalls are configured to allow IPv6 traffic on the [GameStream ports](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide#other-firewall-software). This tool will automatically create firewall exceptions in PCP-compatible routers, but you will need to do this manually on some routers.
2. Make sure that both your gaming PC and Moonlight client device have IPv6 connectivity on their active networks using a site like http://test-ipv6.com/
