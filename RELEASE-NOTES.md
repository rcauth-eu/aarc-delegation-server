# RELEASE NOTES

## Version 0.2.0

If you are upgrading from a previous release, you will need to make several
changes:

#### Update the server config file `/var/www/server/conf/cfg.xml`

* Add the following attributes to the relevant `<service>` element(s):
    * `disableDefaultStores="false"`
    * `OIDCEnabled="true"`

  The latter is currently optional, being the default setting.

* Change the name of the scopehandler

        org.delegserver.oauth2.DSDynamicScopeHandler

  into

        eu.rcauth.delegserver.oauth2.DSDynamicClaimsSourceImpl

* Change the names of each of the attributeFilters, for example

        org.delegserver.oauth2.shib.filters.URLDomainNameFilter

  into

        eu.rcauth.delegserver.oauth2.shib.filters.URLDomainNameFilter

  and likewise for any other attribute filter.

* Make sure you have a `defaultKeyID` attribute specified in the `JSONWebKey` element, e.g.

       <JSONWebKey defaultKeyID="71463FFC64B4394DD96F29484E9BFB0A">
           <path>/var/www/server/conf/ds.jwk</path>
       </JSONWebKey>

  where the `defaultKeyID` value should match one of the `kid` values in the `ds.jwk` file.

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

  You can run something like:

        update clients set scopes = '["openid","email","profile","edu.uiuc.ncsa.myproxy.getcert"]';

  or

        update clients set scopes = '["openid"]' where name = "SSH Key portal;

#### Effective request scopes

The effective list of scopes used in a request is the intersection of:

1. the scopes in the request itself,
2. the scopes configured as above for the specific client,
3. the scopes enabled for the server.  
   This typically includes the basic scopes
   (`openid`, `email`, `profile` and `edu.uiuc.ncsa.myproxy.getcert`)
   plus any other scopes such as `org.cilogon.userinfo` that are added to the
   `<scopes>` node of the `cfg.xml`.  
   Note that the basic scopes can be disabled using the `enabled="false"` attribute.
