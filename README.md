# Implementation-of-mDNS-and-DNS.-Demo-Application.

## Requirements:
Use the socket module exclusively for communication. DNS/mDNS packet implementation:
  1. Support DNS-SD (DNS Service Discovery) packet structures.
  2. Include record types: SRV (service location), PTR (pointer), and A (address).

## Demo Application
1. Monitoring Script
  Functionality:

    Monitor one or more system resources (CPU load, memory usage, temperatures, etc.).

    Allow resource selection via a configurable interface.

  DNS-SD Integration:

  Expose monitored resources as DNS-SD services:

    SRV records: Map resources to services.

    PTR records: Associate services with a user-configured hostname.

    TXT records: Store real-time monitored values (e.g., cpu_load=45%).

  2. Discovery Script
    Functionality:

      Detect available services in the local network.

      Display the IP address and resource value when a service entry is selected.

    Features:

      Caching: Implement a caching mechanism to reduce redundant queries.

      TTL control: Allow TTL (Time-to-Live) adjustments in the monitoring script.
