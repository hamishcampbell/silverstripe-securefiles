<?php
/**
 * Traverses asset folders re-building the correct
 * htaccess rules for your secure file configuration.
 * Run after importing a database, manually adding folders,
 * modifying your htaccess ruleset, etc.
 *
 * @package securefiles
 * @subpackage tasks
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileCheckFolders extends BuildTask {
	
	protected $title = 'Apply Secure File Access Rules';
	
	protected $description = 'Traverses your asset file structure rebuilding/removing htaccess rules as appropriate.';
	
	public function run($request) {
		if(!Director::is_cli()) echo "<pre>";
		echo "* Sync filesystem with database...\n";
		echo "* " . FileSystem::sync() . "\n";
		echo "* Applying secure file rules...\n";
		
		$secure = 0; $unsecure = 0;
		$folders = DataObject::get('Folder');
		
		if($folders) {
			foreach($folders as $folder) {
				$folder->Secured ? $secure++ : $unsecure++;
				$folder->forceChange();
				$folder->write();
				
			}
			echo "* " . $folders->Count() . " folders processed:  $secure secure, $unsecure unsecure\n";
		} else {
			echo "* No folders found!\n";
		}
		
		echo "* Task finished.\n";
		if(!Director::is_cli()) echo "</pre>";
	}
	
}
