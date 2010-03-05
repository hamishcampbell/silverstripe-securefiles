<?php
/**
 * Stores token records for file permissions
 * @see SecureFileTokenPermissionDecorator
 *
 * @package securefiles
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
	);
	
	static $has_many = array(
	);
	
	static $many_many = array(
	);
	
	static $belongs_many_many = array(
	);
	
	static $summary_fields = array(
		'Name' => 'Name', 
		'ExpiryNice' => 'Expiry', 
		'TokenedAbsoluteURL' => 'URL'
	);

	static $casting = array(
		'ExpiryNice' => 'Varchar',
	);
	
	/**
	 * Get the file name for this access token record
	 * @return string
	 */
	function getName() {
		return $this->File()->Name;
	}

	/**
	 * Get the URL for this access token record
	 * @return string
	 */
	function getURL() {
		return $this->File()->URL;		
	}
	
	/**
	 * Get the absolute tokened URL path to access this file
	 * @return string
	 */
	function getTokenedAbsoluteURL() {
		return Controller::join_links(Director::absoluteBaseURL() . $this->File()->getFilename(), "?token=" . $this->Token);
	}
	
	/**
	 * Get the relative tokened URL path to access this file
	 * @return string
	 */
	function getTokenedURL() {
		return Controller::join_links($this->File()->URL, "?token=" . $this->Token);
	}
	
	/**
	 * Return a nicely formatted expiry time
	 * @return string
	 */
	function ExpiryNice() {
		if($this->Expiry) {
			$expiry = $this->dbObject('Expiry');
			return $expiry->Ago();
		} else {
			return _t('SecureFiles.NEVEREXPIRES', 'Never');
		}
	}
	
	function getCMSFields() {
		
		if($this->FolderID) {
			// New token - select file:
			$folder = DataObject::get_by_id('Folder', $this->FolderID);
			$files = new DataObjectSet();
			if($folder->myChildren()) {
				foreach($folder->myChildren() as $file) {
					if(!($file instanceof Folder))
						$files->push($file);
				}
				$files->sort('Name');
			}
			$fileField = new DropdownField('FileID', 'File', $files->map('ID', 'Name'));
		} else {
			// Existing token:
			$fileField = new ReadonlyField('FileDummy', 'File', $this->File()->Name);
		}
						
		$fields = new FieldSet();
		$fields->push($root = new TabSet('Root'));
		$root->push($main = new Tab('Main'));
		$main->push($fileField);
		$main->push(new DatetimeField('Expiry', 'Expiry'));
		if($this->ID)
			$main->push(new ReadonlyField('Token', 'Token'));
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
		parent::onBeforeWrite();
		if($this->Token == '')
			$this->Token = $this->generateHash();
	}
	
	
	
}
