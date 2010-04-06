<?php
/**
 * Creates a token based permission system for files
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileTokenPermissionDecorator extends DataObjectDecorator {
	
	function extraStatics() {
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
	public function updateCMSFields(FieldSet &$fields) {
		
		// Only modify file objects with parent nodes
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
			
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return;
		
		// Update Security Tab
		$secureFilesTab = $fields->findOrMakeTab('Root.'._t('SecureFiles.SECUREFILETABNAME', 'Security'));	
		$secureFilesTab->push(new HeaderField(_t('SecureFiles.TOKENACCESSTITLE', 'Token Access')));
		
		if(!$this->owner->containsFiles()) { 
			$secureFilesTab->push(new ReadonlyField('DummyTokenList', '', _t('SecureFiles.NOFILESINFOLDER', 'There are no files in this folder.')));
			return;
		}
		
		$secureFilesTab->push($tokenList = new ComplexTableField(
			$this->owner,
			'ContainedFileTokens',
			'SecureFileAccessToken',
			null,
			null,
			"File.ParentID = '{$this->owner->ID}'",
			$sourceSort = null,
			"JOIN File ON FileID = File.ID"
		));
		$tokenList->setParentIdName('FolderID');
		$tokenList->setRelationAutoSetting(false);
		
		// Remove add link if there are no files in this folder
		if(!$this->owner->containsFiles()) 
			$tokenList->setPermissions(array('edit', 'delete'));
				
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
		$this->extend('onAfterGenerateToken', $token);
		return $token;
	}
	
	/**
	 * When the object is deleted, remove file access tokens that might be hanging around.
	 * @see sapphire/core/model/DataObjectDecorator#onAfterDelete()
	 */
	function onAfterDelete() {
		$tokens = DataObject::get('SecureFileAccessToken', "FileID = '".Convert::raw2sql($this->owner->ID)."'");
		if($tokens)
			foreach($tokens as $token)
				$token->delete();
	}
	
}
