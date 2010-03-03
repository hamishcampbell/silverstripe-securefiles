<?php
/**
 * Adds required fields and methods to File objects
 *
 * @package securefiles
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
		if(!Permission::checkMember($member, array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return; 
			
		$secureFilesTab = $fields->findOrMakeTab('Root.'._t('SecureFiles.SECUREFILETABNAME', 'Security'));		
		$EnableSecurityField = ($this->InheritSecured()) 
			? new LiteralField('InheritSecurity', _t('SecureFiles.INHERITED', 'This folder is inheriting security settings from a parent folder.'))
			: new CheckboxField('Secured', _t('SecureFiles.SECUREFOLDER', 'Folder is secure.'));			
		
		$secureFilesTab->push(new HeaderField(_t('SecureFiles.FOLDERSECURITY', 'Folder Security')));
		$secureFilesTab->push($EnableSecurityField);
	
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
			$htaccess = $this->owner->getFullPath().SecureFileController::$htaccess_file;
			if($this->owner->Secured && !file_exists($htaccess)) {
				file_put_contents($htaccess, SecureFileController::HtaccessRules());				
			} elseif(!$this->owner->Secured && file_exists($htaccess)) {
				unlink($htaccess);
			}
		}
	}
	
}

