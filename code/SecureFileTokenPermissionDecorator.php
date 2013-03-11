<?php
/**
 * Creates a token based permission system for files
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileTokenPermissionDecorator extends DataExtension {
	
	function extraStatics($class = null, $extension = null) {
		return array(
			'has_many' => array(
				'AccessTokens' => 'SecureFileAccessToken',
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
		if(!isset($_REQUEST['token']))
			return false;
		$token_SQL = Convert::raw2sql($_REQUEST['token']);
		$memberFilter_SQL = "(MemberID IS NULL OR MemberID = 0)";
		if($member)
			$memberFilter_SQL .= " OR MemberID = '" . (is_object($member) ? $member->ID : (int)$member) . "'";
		$tokens = $this->owner->AccessTokens("Token = '{$token_SQL}' AND (Expiry IS NULL OR Expiry > NOW()) AND ({$memberFilter_SQL})");
		return $tokens->exists();
	}
	
	/**
	 * Returns true if the folder contains files
	 * @return boolean
	 */
	public function containsFiles() {
		if(!($this->owner instanceof Folder))
			return false;
		return (bool)DB::query("SELECT COUNT(*) FROM File WHERE ParentID = "
			. (int)$this->owner->ID . " AND ClassName NOT IN ('". implode("','", array_values(ClassInfo::subclassesFor('Folder'))) . "')")->value();		
	}
	
	/**
	 * Adds token creation fields to CMS
	 * 
 	 * @param FieldSet $fields
 	 * @return void
 	 */
	public function updateCMSFields(FieldList $fields) {
		
		// Only modify file objects with parent nodes
		if( $this->owner instanceof Folder || !$this->owner->ID || !($this->owner instanceof File))
			return;
		
		// Only if parent folder is secure
		if ( !$this->owner->Parent()->Secured ) return;
		
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return;
		
		// Update Security Tab
		$security = $fields->fieldByName('Security');
		if (!$security) {
			$security = ToggleCompositeField::create('Security', _t('SecureFiles.SECUREFILETABNAME', 'Security'), array())->setHeadingLevel(4);
		}
		
		$tokenList = GridField::create('AccessTokens', _t('SecureFiles.TOKENACCESSTITLE', 'Token Access'), $this->owner->AccessTokens(), SecureFileAccessToken::getGridFieldConfig());
		$security->push($tokenList);
		
		$fields->push($security);		
	}
	
	/**
	 * API method to create and return a new access token for a file.
	 * 
	 * @param $expiry int|string Either a unix timestamp or a strtotime compatable datetime string
	 * @param $member int|Member Either a valid member ID or a member object
	 * @return SecureFileAccessToken
	 */
	public function generateAccessToken($expiry = null, $member = null) {
		if($this->owner instanceof Folder)
			return false;
		$token = new SecureFileAccessToken();
		$token->FileID = $this->owner->ID;
		if($expiry)
			$token->Expiry = is_int($expiry) ? $expiry : strtotime($expiry);
		if($member)
			$token->MemberID = is_object($member) ? $member->ID : (int)$member;
		$token->write();
		$this->owner->extend('onAfterGenerateToken', $token);
		return $token;
	}
	
	/**
	 * When the object is deleted, remove file access tokens that might be hanging around.
	 * @see framework/core/model/DataObjectDecorator#onAfterDelete()
	 */
	function onAfterDelete() {
		$tokens = DataObject::get('SecureFileAccessToken', "FileID = '".Convert::raw2sql($this->owner->ID)."'");
		if($tokens)
			foreach($tokens as $token)
				$token->delete();
	}
	
}
