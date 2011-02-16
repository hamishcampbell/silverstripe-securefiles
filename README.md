# Secure Files Module

Adds a variety of security controls to your SilverStripe file assets.

## Maintainer Contact

 *  Hamish Campbell <hn.campbell (at) gmail (dot) com>

## Requirements

 *  SilverStripe 2.3,x, 2.4

## Installation Instructions

 1.  Extract the module to your website directory.
 2.  Run /dev/build?flush=1
 3.  Optionally apply the additional permission modes listed in _config.php
   
## Usage Overview

Adds a "Security" tab to the Folder options in
Asset Administration. From here you can turn
security on/off and set who can view the asset.

Securing files will cause extra load on your
webserver and your database, as sapphire will check
the datatabase for access permissions, and pass the
data through sapphire when it is output to the user.

At the most basic level, ADMINISTRATOR users and users
with the SECUREFILEACCESS permission will always be 
granted access to files.  

Any or all of the additional systems can be enabled:

 *  Group Permission: assign groups that are premitted 
    to access the file by folder. Inherits 
    permissions from parent folders.
 *  Member Permission: assign permission to folders to
    individual members. Inherits permissions from 
    parent folders. 
 *  Token Permissoin: generate a unique URL the grants 
    access to the file. Optionally set an expiry 
    date

Only ADMINISTRATOR users or users with the the 
SECUREFILESETTINGS permission are able to edit folder 
security settings in the CMS.

## Recommendations

 *  This module uses htaccess rules and mod_rewrite.
    If you're using SilverStripe in rewriteless mode
    (using the base index.php) or via IIS, DO NOT
    USE THIS MODULE.
  
 *  Disable all Apache Option directives for your 
    asset folders from your Apache configuration
    (eg httpd.conf). Prevents directory indexing,
    includes, symlinking and CGI execution:
        <Directory /www/assets>
          Options None
        </Directory>
  
 *  For large files, streaming media or a general
    performance boost, use mod_xsendfile (for apache)
    or lighttpd (uses xsendfile natively). Enable xsendfile
    headers with Secure Files by adding this to your
    _config.php:
        SecureFileController::use_x_sendfile_method();
  
## Developer Tips
 
 *  Create new access methods by decorating File and
    implementing the canViewSecured method. If it returns
    true access to the file is granted.
  
 *  Hooks are provided for onAccessGranted and 
    onAccessDenied. Implement these methods in your
    decorators to trigger actions when the file is 
    requested (eg, access logging).
  
 *  The token access permission provides the capability
    to link tokens to specific users by supplying a valid
    member ID. This is not used within the default
    administration of Secure Files, but is provided as 
    an option for developers to facilitate other content
    delivery options (eg, paid for downloads).
  
##  Disclaimer

ADDITIONAL COMMENTARY TO THE LICENSE DISCLAIMER:
This module is intended to provide an additional 
level of control and security over your uploaded 
assets, HOWEVER there is no guarantee that this 
module is 100% secure, that other code on your 
website or server allows alternative methods of 
accessing your files or that future changes to 
your webserver configuration or SilverStripe 
installation will now allow this protection to 
be bypassed. Use at your own risk.
