# aarc-delegation-server

The AARC delegation server is an implementation of the Delegation Server component,
acting as a webfrontend for the [RCauth.eu online CA](https://rcauth.eu/).  
It is based on a customised version of the
[OA4MP](https://github.com/rcauth-eu/OA4MP).

For release notes and important upgrading information,
see [RELEASE-NOTES.md](RELEASE-NOTES.md).

## Implementation
The Delegation Server acts as both an OpenID Connect provider and protected
resource, providing end-entity certificates from its backend online CA to its
clients using OAuth2 authorization flows.  
Clients are typically Master Portals such as the
[AARC Master Portal](https://github.com/rcauth-eu/aarc-master-portal).

## Compiling

1. You first need to compile and install the two RCauth-adapted dependency
   libraries 
    1. [security-lib](https://github.com/rcauth-eu/security-lib) (RCauth version)
    2. [OA4MP](https://github.com/rcauth-eu/OA4MP) (RCauth version)
   
   Make sure to use the *same* version (branch or tag) for both the
   security-lib and OA4MP components.  
   For the **0.2** series of the aarc-delegation-server, you must use the
   **4.2-RCauth** versions.
   
2. Checkout the right version of the aarc-delegation-server.

        git clone https://github.com/rcauth-eu/aarc-delegation-server
        cd aarc-delegation-server

        git checkout v0.2.6
        cd delegation-server

3. Build the delegation-server's war file  

        mvn clean package

   After maven has finished you should find the `.war` file in the target
   directory:

        aarc-delegation-server/delegation-server/target/oauth2.war
    
4. Build the delegation-server's command line client

        mvn -P cli package

   After mvn has finished you should find the resulting cli `.jar` file
   in the target directory:
   
        aarc-delegation-server/delegation-server/target/oa2-cli.jar
   
   NOTE: The cli tool is necessary for managing and approving client
   (Master Portal) registrations.  
   Also note that you need this version of the cli tool, as opposed to the one
   coming from the OA4MP component.  

## Other Resources

Background information:
* [RCauth.eu and MasterPortal architecture](https://wiki.nikhef.nl/grid/RCauth.eu_and_MasterPortal_architecture)
* [RCauth.eu and MasterPortal documentation](https://wiki.nikhef.nl/grid/RCauth.eu_and_MasterPortal_documentation)
* [Ansible scripts for the Delegation Server](https://github.com/rcauth-eu/aarc-ansible-delegation-server)

Related Components:
* [AARC Master Portal](https://github.com/rcauth-eu/aarc-master-portal).
* [Demo VO portal](https://github.com/rcauth-eu/aarc-vo-portal)  
  this component can run inside the master portal's tomcat container,
  providing a demonstration client portal to the Master Portal.
* [SSH key portal](https://github.com/rcauth-eu/aarc-ssh-portal)  
  this component can run inside the master portal's tomcat container,
  leveraging the Master Portal's sshkey upload endpoint.
