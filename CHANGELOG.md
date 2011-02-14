# Changelog

## Development

  - Added MODULE_SECUREFILES_PATH constant to _config.php
  - Updated htaccess ruleset to match SS default
  - Added static accessors to SecureFileController:
      - $htaccess_file now set with set_access_filename()
      - $chuck_size_kb now set with set_chunk_size()
  - Moved access rule generation to SecureFileDecorator
  - Added modifyAccessRules hook to edit access ruleset
  - Updated test cases (particularly to fix whitelisting issue)
  - CSS tweaks in CMS

## 0.30

  - Added onAccessGranted and onAccessDenied hooks for File
  - DateField compatibility fixes
  - Member access token permission option
  - Support for x-sendfile module and fread send method
  - Added tests for basic operations
  - Added buildtask to rebuild htaccess files
  - Translations: German, Spanish, Finnish, French and Swedish
  
## 0.21

  - Minor bugfix release

## 0.20

  - Improved 2.4 compatibility
  - Better i18n support
  - Member permission option
  - CMS administration improvements
  

## 0.10

  - Initial release
  - Abstracted security method
  - Group permission option