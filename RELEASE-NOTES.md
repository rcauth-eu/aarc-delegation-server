# RELEASE NOTES

## Version 0.2.0

If you are upgrading from a previous release, you will need to make several
changes:

#### Update the server config file `/var/www/server/conf/cfg.xml`

* Add the following attributes to the relevant `<service>` element(s):
    * `disableDefaultStores="false"`
    * `OIDCEnabled="true"`

  The latter is optional, being the default setting.

* Make sure you have a `defaultKeyID` attribute specified in the `JSONWebKey`
  element, e.g.

       <JSONWebKey defaultKeyID="71463FFC64B4394DD96F29484E9BFB0A">
           <path>/var/www/server/conf/ds.jwk</path>
       </JSONWebKey>

  where the `defaultKeyID` value should match one of the `kid` values in the
  `ds.jwk` file.

* Change the name of the scopes handler

        org.delegserver.oauth2.DSDynamicScopeHandler

  into

        eu.rcauth.delegserver.oauth2.DSDynamicClaimsSourceImpl

* Change the names of each of the attributeFilters, for example

        org.delegserver.oauth2.shib.filters.URLDomainNameFilter

  into

        eu.rcauth.delegserver.oauth2.shib.filters.URLDomainNameFilter

  and likewise for any other attribute filter.

* Add the following two new tables to the mysql schema:

        <permissions/>
        <adminClients/>

  These are necessary for the new client management API described below.

#### Register the scopes for each client

Scope handling has changed and it is now necessary to explicitly enable the set
of supported scopes for each client separately.  
In order to do this, you can either:

* use the 0.2.0 version of the `oa2-cli` commandline tool, and update each
  client separately:

        /var/www/server/tools/oa2-cli
        > use clients
        > update 0
        > ...

  NOTE you will need to adapt the server `/var/www/server/conf/cfg.xml` first,
  following the instructions above.

* Alternatively, use the `mysql` commandline tool
  (username, password and database can be found in `cfg.xml`).

  *Make a backup of the client database first, e.g. using `mysqldump`!!*

  You can run a mysql command such as:

        update clients set scopes = '["openid","email","profile","edu.uiuc.ncsa.myproxy.getcert"]';

  or

        update clients set scopes = '["openid"]' where name = "SSH Key portal;

#### Mail support

In order to use [mail notifications](http://grid.ncsa.illinois.edu/myproxy/oauth/server/configuration/server-email.xhtml)
it is now necessary to provide tomcat with the `javax.mail.jar` file.  
The easiest is to create a symlink to the the jar file as shipped by
the `javamail` rpm:

    ln -s /usr/share/java/javamail/javax.mail.jar /usr/share/java/tomcat/

#### Effective request scopes

The effective list of scopes used in a request is the intersection of:

1. the scopes in the request itself,
2. the scopes configured as above for the specific client,
3. the scopes enabled for the server.  
   This typically includes the basic scopes
   (`openid`, `email`, `profile` and `edu.uiuc.ncsa.myproxy.getcert`)
   plus any other scopes such as `org.cilogon.userinfo` that are added to the
   `<scopes>` node of the `cfg.xml`.  
   Note that the basic scopes can be disabled using the `enabled="false"`
   attribute.

#### Client management API

It is now possible to manage clients (i.e. MasterPortals) also using a
JSON-based REST API (`/clients`) making use of special administrative client
credentials. Those admin clients can be registered using the administrative
client registration endpoint (`/admin-register`) and still need to be approved
using the command line tool (`use admins`). The API allows e.g. to create,
approve, list, update and remove clients.  
For examples and description, see
[oa4mp-server-admin-oauth2](https://github.com/rcauth-eu/OA4MP/tree/rcauth-4.2/oa4mp-server-admin-oauth2/src/main/scripts/client-scripts).

#### Other new features

Apart from the above changes, it is now possible to configure a client (i.e. a
MasterPortal) to *only* receive limited proxies.

Note that this means that *all* the clients to that MasterPortal itself will
also *only* receive limited proxies. This could be useful if those clients just
need to access storage and not use the proxies for job submission.
