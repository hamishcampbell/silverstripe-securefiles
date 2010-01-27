<?php
/**
 * Creates a group based permission system for files
 *
 * @package securefiles
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

	function canView(Member $member = null) {
		if($this->owner->basicViewChecks($member))
			return true;
		if(!$member)
			return false;
		return $member->inGroups($this->owner->AllGroupPermissions());
	}
	
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
	
	function InheritedGroupPermissions() {
		if($this->owner->ParentID)
			return $this->owner->Parent()->AllGroupPermissions();
		else
			return new DataObjectSet();
	}
	
	/**
	 * Security tab for folders
	 */
	public function updateCMSFields(FieldSet &$fields) {
		
			if(!($this->owner instanceof Folder) || !$this->owner->ID)
				return;

			$GroupTreeField = new TreeMultiselectField('GroupPermissions', 'Group Access');	
			
			$fields->addFieldToTab('Root.Security',	new HeaderField('Group Access'));
			$fields->addFieldToTab('Root.Security', $GroupTreeField);	
				
			if($this->owner->InheritSecured()) {
				$permissionGroups = $this->owner->InheritedGroupPermissions();
				if($permissionGroups->Count()) {
					$fieldText = implode(", ", $permissionGroups->map());
				} else {
					$fieldText = "(None)";
				}
				$InheritedGroupsField = new ReadonlyField("InheritedGroupPermissionsText", "Inherited Group Permissions", $fieldText);
				$fields->addFieldToTab('Root.Security', $InheritedGroupsField);
			}
				

			
	}
	
}


?>