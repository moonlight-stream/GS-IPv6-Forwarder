# GameStream IPv6 Forwarder
Current versions of GeForce Experience do not listen on IPv6 for connections from GameStream clients by default.

Running this forwarding service on the GameStream host allows Moonlight clients to access it over IPv6. This can allow Moonlight access to multiple PCs behind a single router without port forwarding.

This tool is intended for very experienced users that are familar with IPv6 configuration. Most users should use port forwarding instead.

# Instructions
1. Download MSI package from the [GitHub Releases](https://github.com/moonlight-stream/GS-IPv6-Forwarder/releases) page.
2. Install the package on your gaming PC. The service will run automatically in the background.
4. Ensure your router's IPv6 firewall is configured to allow the GameStream ports (TCP 47984, 47989, 48010 and UDP 47998, 47999, 48000, 48002, 48010)
3. Give it a try! Connect via Moonlight using an IPv6 address or host name.

# Troubleshooting
1. Make sure that your router and PC firewalls are configured to allow IPv6 traffic on the GameStream ports. Typically, IPv6 firewall settings are completely separate from IPv4 firewall settings.
2. Make sure that both your gaming PC and Moonlight client device have IPv6 connectivity on their active networks using a site like http://test-ipv6.com/
