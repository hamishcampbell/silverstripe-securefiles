<?php
/**
 * Creates a group based permission system for files
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileGroupPermissionDecorator extends DataObjectDecorator {
	
	function extraStatics() {
		return array(
			'many_many' => array(
				'GroupPermissions' => 'Group',
			),
		);
	}
	
	/**
	 * View permission check
	 * 
	 * @param Member $member
	 * @return boolean
	 */
	function canViewSecured(Member $member = null) {
		return $member ? $member->inGroups($this->owner->AllGroupPermissions()) : false;
	}
	
	/**
	 * Collate permissions for this and all parent folders.
	 * 
	 * @return DataObjectSet
	 */
	function AllGroupPermissions() {
		$groupSet = new DataObjectSet();
		$groups = $this->owner->GroupPermissions();
		foreach($groups as $group)
			$groupSet->push($group);
		if($this->owner->ParentID)
			$groupSet->merge($this->owner->InheritedGroupPermissions());
		$groupSet->removeDuplicates();
		return $groupSet;
	}
	
	/**
	 * Collate permissions for all parent folders
	 * 
	 * @return DataObjectSet
	 */
	function InheritedGroupPermissions() {
		if($this->owner->ParentID)
			return $this->owner->Parent()->AllGroupPermissions();
		else
			return new DataObjectSet();
	}
	
	/**
	 * Adds group select fields to CMS
	 * 
 	 * @param FieldSet $fields
 	 * @return void
 	 */
	public function updateCMSFields(FieldSet &$fields) {
		
		// Only modify folder objects with parent nodes
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
			
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return;
		
		// Update Security Tab
		$secureFilesTab = $fields->findOrMakeTab('Root.'._t('SecureFiles.SECUREFILETABNAME', 'Security'));
		$secureFilesTab->push(new HeaderField(_t('SecureFiles.GROUPACCESSTITLE', 'Group Access')));
		$secureFilesTab->push(new TreeMultiselectField('GroupPermissions', _t('SecureFiles.GROUPACCESSFIELD', 'Group Access Permissions')));	
			
		if($this->owner->InheritSecured()) {
			$permissionGroups = $this->owner->InheritedGroupPermissions();
			if($permissionGroups->Count()) {
				$fieldText = implode(", ", $permissionGroups->map());
			} else {
				$fieldText = _t('SecureFiles.NONE', "(None)");
			}
			$InheritedGroupsField = new ReadonlyField("InheritedGroupPermissionsText", _t('SecureFiles.GROUPINHERITEDPERMS', 'Inherited Group Permissions'), $fieldText);
			$InheritedGroupsField->addExtraClass('prependUnlock');
			$secureFilesTab->push($InheritedGroupsField);
		}
	}
}
