<?php
/**
 * Secure File Permission Object
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFilePermission extends DataObject {
	
	static $default_sort = "";

	static $singular_name = "File Permission";

	static $plural_name = "File Permissions";
	
	static $db = array(
		'SecureCanView' => 'Boolean',
	);

	static $indexes = array();

	static $has_one = array(
		'File' => 'File',
		'Member' => 'Member',
	);
	
	static $has_many = array();
	
	static $many_many = array();

	static $belongs_many_many = array();
	
	static $extensions = array();
	
	static $defaults = array(
		'SecureCanView' => false,
	);

	static $summary_fields = array(
		'Member.Name',
		'File.Name',
		'SecureCanView',
	);
	
	static $searchable_fields = array(
		'Member.ID',
		'File.ID',
		'SecureCanView',
	);
	
	/**
	 * Sync the filesystem and for each folder
	 * that has an htaccess file, mark the folder
	 * as secure
	 */
	function requireDefaultRecords() {
		Filesystem::sync();
		$folders = DataObject::get("Folder");
		if($folders) {
			foreach($folders as $folder) {
				if(file_exists($folder->FullPath.SecureFileController::$htaccessfile)) {
					$folder->Secured = true;
					$folder->write();
				}
			}
		}
	}
	
}
?>