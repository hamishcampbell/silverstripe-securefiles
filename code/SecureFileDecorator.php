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
	
	function canView($member = null) {
		if($this->owner->basicViewChecks($member))
			return true;
	}
	
	function basicViewChecks($member = null) {
		if(Permission::checkMember($member, array('ADMIN', 'SECURE_FILE_ACCESS'))) 
			return true;
		if(!$this->owner->Secured && !$this->owner->InheritSecured())
			return true;
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
		
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
		
		$EnableSecurityField = ($this->InheritSecured()) 
			? new LiteralField('InheritSecurity', _t('SecureFiles.INHERITED', 'This folder is inheriting security settings from a parent folder.'))
			: new CheckboxField('Secured', _t('SecureFiles.SECUREFOLDER', 'Folder is secure.'));			
		
		$fields->addFieldToTab('Root.Security',	new HeaderField('Folder Security'));
		$fields->addFieldToTab('Root.Security', $EnableSecurityField);
	
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
?>
