<?php
/**
 * Stores token records for file permissions
 * @see SecureFileTokenPermissionDecorator
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileAccessToken extends DataObject {
	
	static $singular_name = "File Access Token";
	
	static $plural_name = "File Access Tokens";
	
	static $db = array(
		'Token' => 'Varchar(32)',
		'Expiry' => 'Datetime',
	);
	
	static $has_one = array(
		'File' => 'File',
		'Member' => 'Member',
	);
	
	static $has_many = array(
	);
	
	static $many_many = array(
	);
	
	static $belongs_many_many = array(
	);
	
	static $summary_fields = array(
		'Name' => 'Name', 
		'MemberNice' => 'Member',
		'ExpiryNice' => 'Expiry', 
		'TokenedAbsoluteURL' => 'URL'
	);
	
	static $casting = array(
		'ExpiryNice' => 'Varchar',
		'MemberNice' => 'Varchar',
	);
	
	/**
	 * Get the file name for this access token record
	 * @return string
	 */
	public function getName() {
		return $this->File()->Name;
	}
	
	/**
	 * Get the URL for this access token record
	 * @return string
	 */
	public function getURL() {
		return $this->File()->URL;		
	}
	
	/**
	 * Get the absolute tokened URL path to access this file
	 * @return string
	 */
	public function getTokenedAbsoluteURL() {
		return Controller::join_links(Director::absoluteBaseURL() . $this->File()->getFilename(), "?token=" . $this->Token);
	}
	
	/**
	 * Get the relative tokened URL path to access this file
	 * @return string
	 */
	public function getTokenedURL() {
		return Controller::join_links($this->File()->URL, "?token=" . $this->Token);
	}
	
	/**
	 * Return a nicely formatted expiry time
	 * @return string
	 */
	protected function ExpiryNice() {
		if($this->Expiry) {
			$expiry = $this->dbObject('Expiry');
			return $expiry->Ago();
		} else {
			return _t('SecureFiles.NEVEREXPIRES', 'Never');
		}
	}
	
	/**
	 * Return a nicely formatted description of the member who has access
	 * @return string
	 */
	protected function MemberNice() {
		if($this->MemberID)
			return $this->Member()->Name;
		else
			return _t('SecureFiles.EVERYONE', 'Everyone');
	}
	
	/**
	 * @return GridFieldConfig A config suitable for displaying a list of SecureFileAccessTokens.
	 */
	public static function getGridFieldConfig() {
		$config = GridFieldConfig::create();
		$config->addComponent(new GridFieldButtonRow('before'));
		$config->addComponent(new GridFieldAddNewButton('buttons-before-left'));
		$config->addComponent(new GridFieldToolbarHeader());
		$config->addComponent(new GridFieldDataColumns());
		$config->addComponent(new GridFieldEditButton());
		$config->addComponent(new GridFieldDeleteAction());
		$config->addComponent(new GridFieldPaginator(30));
		$config->addComponent(new GridFieldDetailForm());
		
		return $config;
	}
	
	function getCMSFields() {
		$fields = new FieldList();
		$fields->push($expiry_field = new DatetimeField('Expiry', 'Expiry'));
		$expiry_field->getDateField()->setConfig('showcalendar', true);
		$expiry_field->getTimeField()->setConfig('showdropdown', true);
		
		$fields->push(new ReadonlyField('MemberDummyField', 'Member', $this->MemberNice()));
		if($this->ID)
			$fields->push(new ReadonlyField('Token', 'Token'));
		$this->extend('updateCMSFields', $fields);
		return $fields;
	}
	
	/**
	 * Generate a unique and hard to guess MD5 hash for this token.
	 * @return string of 32 characters
	 */
	protected function generateHash() {
		return md5(microtime(true).rand(100000, 999999));
	}
	
	/**
	 * After writing this object, check if it has a valid token. If not, generate one!
	 */
	function onBeforeWrite() {
		if($this->Token == '')
			$this->Token = $this->generateHash();
		parent::onBeforeWrite();
	}
	
	
	
}
