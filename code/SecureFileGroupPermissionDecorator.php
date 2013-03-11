<?php
/**
 * Creates a group based permission system for files
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileGroupPermissionDecorator extends DataExtension {
	function extraStatics($class = null, $extension = null) {
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
		$groupSet = new ArrayList();
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
			return new ArrayList();
	}
	
	/**
	 * Adds group select fields to CMS
	 * 
 	 * @param FieldSet $fields
 	 * @return void
 	 */
	public function updateCMSFields(FieldList $fields) {
		
		// Only modify folder objects with parent nodes
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
			
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return;
		
		// Update Security Tab
		$security = $fields->fieldByName('Security');
		if (!$security) {
			$security = ToggleCompositeField::create('Security', _t('SecureFiles.SECUREFILETABNAME', 'Security'), array())->setHeadingLevel(4);
		}
		
		$security->push(new HeaderField(_t('SecureFiles.GROUPACCESSTITLE', 'Group Access')));
		$security->push(new TreeMultiselectField('GroupPermissions', _t('SecureFiles.GROUPACCESSFIELD', 'Group Access Permissions')));	
			
		if($this->owner->InheritSecured()) {
			$permissionGroups = $this->owner->InheritedGroupPermissions();
			if($permissionGroups->Count()) {
				$fieldText = implode(", ", $permissionGroups->map());
			} else {
				$fieldText = _t('SecureFiles.NONE', "(None)");
			}
			$InheritedGroupsField = new ReadonlyField("InheritedGroupPermissionsText", _t('SecureFiles.GROUPINHERITEDPERMS', 'Inherited Group Permissions'), $fieldText);
			$InheritedGroupsField->addExtraClass('prependUnlock');
			$security->push($InheritedGroupsField);
		}
	}
}
