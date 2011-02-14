<?php
/**
 * Adds required fields and methods to File objects
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileDecorator extends DataObjectDecorator {
	
	function extraStatics() {
		return array(
			'db' => array(
				'Secured' => 'Boolean',
			),
		);
	}
	
	/**
	 * canViewSecured informs Secure Files whether the user has access to this folder.
	 * Unlike canView(), this searches for any ALLOWED permission, whereas canView will
	 * look for a disallow condition. Implementing canViewSecured allows additional decorators
	 * to provide new access permissions.
	 * 
	 * @param Member $member
	 * @return boolean
	 */
	function canViewSecured($member = null) {
		if(Permission::checkMember($member, array('ADMIN', 'SECURE_FILE_ACCESS'))) 
			return true;
		if(!$this->owner->Secured && !$this->owner->InheritSecured())
			return true;
		return false;
	}
	
	/**
	 * Searches for a valid access permission on applied file decorators
	 * 
	 * @param Member $member
	 * @return boolean
	 */
	function canView($member = null) {
		$values = $this->owner->extend('canViewSecured', $member);
		return max($values);
	}
	
	/**
	 * Are any of this file's parent folders secured
	 * 
	 * @return boolean
	 */
	public function InheritSecured() {
		if($this->owner->ParentID) {
			if($this->owner->Parent()->Secured) return true;
			else return $this->owner->Parent()->InheritSecured();
		} else {
			return false;
		}
	}
	
	/**
	 * Security tab for folders
	 */
	public function updateCMSFields(FieldSet &$fields) {
		
		// Only modify folder objects with parent nodes
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
		
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return; 
			
		$secureFilesTab = $fields->findOrMakeTab('Root.'._t('SecureFiles.SECUREFILETABNAME', 'Security'));
		$EnableSecurityHolder = new FieldGroup();
		$EnableSecurityHolder->addExtraClass('securityFieldHolder');
		if($this->InheritSecured()) {
			$EnableSecurityField = new ReadonlyField('InheritSecurity', '', _t('SecureFiles.INHERITED', 'This folder is inheriting security settings from a parent folder.'));
			$EnableSecurityField->addExtraClass('prependLock');
		} else {
			$EnableSecurityField = new CheckboxField('Secured', _t('SecureFiles.SECUREFOLDER', 'Folder is secure.'));
		}			
		
		$secureFilesTab->push(new HeaderField(_t('SecureFiles.FOLDERSECURITY', 'Folder Security')));
		$EnableSecurityHolder->push($EnableSecurityField);
		$secureFilesTab->push($EnableSecurityHolder);
	
	}
	
	/**
	 * For folders, will need to add or remove the htaccess rules
	 * Assumptions:
	 *  - the folder exists (after write!)
	 *  - no one else is trying to put htaccess rules here
	 *  - (follows from above) existing htaccess file was put there by this module
	 * @todo Add better support for existing htaccess files
	 */
	function onAfterWrite() {
		parent::onAfterWrite();
		if($this->owner instanceof Folder) {
			$htaccess = $this->owner->getFullPath().SecureFileController::get_access_filename();
			if($this->owner->Secured && !file_exists($htaccess)) {
				file_put_contents($htaccess, $this->htaccessContent());				
			} elseif(!$this->owner->Secured && file_exists($htaccess)) {
				unlink($htaccess);
			}
		}
	}
	
	/**
	 * Secure files htaccess rules
	 * Rules can be modified by decorators with the extension method
	 * modifyAccessRules`. It is passed an array of named rules that
	 * can be modified. The array is imploded with newlines to produce
	 * the final Apache access ruleset.
	 * 
	 * @return string
	 */	
	function htaccessContent() {
		$rewriteRules =  array(
			'xsendfile' => "<IfModule xsendfile_module>\n" .
				"	XSendFile on \n" . 
				"</IfModule>",
			'php_handler' => "AddHandler default-handler php phtml php3 php4 php5 inc",
				"<IfModule mod_php5.c>\n" .
				"	php_flag engine off\n" .
				"</IfModule>",
			'rewrite_engine' => "RewriteEngine On\n" .
				"RewriteBase " . (BASE_URL ? BASE_URL : "/") . "\n" . 
				"RewriteCond %{REQUEST_URI} ^(.*)$\n" .
				"RewriteRule (.*) " . SAPPHIRE_DIR . "/main.php?url=%1&%{QUERY_STRING} [L]"
		);
		$this->owner->extend('modifyAccessRules', $rewriteRules);
		return implode("\n", $rewriteRules);
	}
	
}

