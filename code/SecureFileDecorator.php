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
			'has_many' => array(
				'MemberPermission' => 'SecureFilePermission',
			),
		);
	}
	
	/**
	 * Returns true if any of this files parent folders is secured
	 */
	public function InheritSecured() {
		if($this->owner->ParentID) {
			if($this->owner->Parent->Secured) return true;
			else return $this->owner->Parent->InheritSecured();
		} else {
			return false;
		}
	}
	
	/**
	 * Returns this objects secure file permissions
	 */
	public function MemberPermissions() {
		return DataObject::get("SecureFilePermission", "FileID = " . $this->owner->ID);
	}

	/**
	 * Recursively merge permissions for this object and its parents
	 */	
	public function AllPermissions() {
		$permissions = $this->MemberPermissions();
		if(!$permissions) $permissions = new DataObjectSet();
		if($this->owner->ParentID) $permissions->merge($this->owner->Parent->AllPermissions());
		return $permissions;
	}
	
	/**
	 * Security tab for folders
	 */
	public function updateCMSFields(FieldSet &$fields) {
		if(($this->owner instanceof Folder) && $this->owner->ID) {
			$fields->addFieldToTab('Root.Security',	new HeaderField('Folder Security'));
			
			$GroupTreeField = new TreeMultiselectField("GroupPermission", "Group Access");

			$TableField = new TableField(
				"MemberPermissions",
				"SecureFilePermission",
				array(
					'MemberID' => _t('Member.NAME', 'Name'),
					'SecureCanView' => _t('SecureFiles.VIEW', 'View'),
				),
				array(
					'MemberID' => 'SecureFileMemberDropdownField',
					'SecureCanView' => 'CheckboxField',
				),
				"FileID",
				$this->owner->ID
			);

			$TableField->setExtraData(array(
				'FileID' => $this->owner->ID ? $this->owner->ID : '$RecordID'
			));
		
			/**
			 * Inherited Security Settings
			 */
			if($this->InheritSecured()) {
				$InheritedPermissions = new TableListField(
					'TableList',
					'SecureFilePermission',
					array(
						'Member.Name' => _t('Member.NAME', 'Name'),
						'File.RelativePath' => _t('HtmlEditorField.FOLDER', 'Folder'),
						'SecureCanView' => _t('SecureFiles.VIEW', 'View'),
					)
				);
				$InheritedPermissions->setFieldCasting(array(
					'SecureCanView' => 'Boolean->Nice',
				));

				$InheritedPermissions->setCustomSourceItems($this->owner->AllPermissions());
				$EnableSecurity = new LiteralField('InheritSecurity', 
						_t('SecureFiles.INHERITED', 'This folder is inheriting security settings from a parent folder.'));
			} else {
				$EnableSecurity = new CheckboxField('Secured', _t('SecureFiles.SECUREFOLDER', 'Folder is secure.'));
				$InheritedPermissions = null;
			}
	
			$fields->addFieldToTab('Root.Security', $EnableSecurity);
			$fields->addFieldToTab('Root.Security', $GroupTreeField);
			$fields->addFieldToTab('Root.Security', $TableField);
			
			if($InheritedPermissions) {
				
				$fields->addFieldToTab('Root.Security', new HeaderField(_t('SecureFiles.ALLPERMISSIONS', 'All Permissions'), 4));
				$fields->addFieldToTab('Root.Security', new LiteralField("InheritedInfo", _t('SecureFiles.INHERITIEDINFO',
					'These permissions summarise the permissions settings on this folder and all ' . 
					'parent folders with permissions set. Note that "NO" settings always take precendence ' .
					'over "YES" settings')));
				$fields->addFieldToTab('Root.Security', $InheritedPermissions);
			}

		}
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
			$htaccess = $this->owner->getFullPath().SecureFileController::$htaccessfile;
			if($this->owner->Secured && !file_exists($htaccess)) {
				file_put_contents($htaccess, SecureFileController::HtaccessRules());				
			} elseif(!$this->owner->Secured && file_exists($htaccess)) {
				unlink($htaccess);				
			}
		}
	}
	
}
?>
