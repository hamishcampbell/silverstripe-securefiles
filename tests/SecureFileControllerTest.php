<?php
/**
 * Test secure file controller for correct access restrictions applied
 *
 * @package securefiles
 * @subpackage tests
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell
 * @todo Implement 
 */
class SecureFileControllerTest extends FunctionalTest {
	
	static $fixture_file = 'securefiles/tests/SecureFileControllerTest.yml';
	
	protected $priorAuthenticators = array();
	
	protected $priorDefaultAuthenticator = null;	
	
	function setUp() {
		parent::setUp();
		
		$this->priorAuthenticators = Authenticator::get_authenticators();
		$this->priorDefaultAuthenticator = Authenticator::get_default_authenticator();
		
		Authenticator::register('MemberAuthenticator');
		Authenticator::set_default_authenticator('MemberAuthenticator');		
		
		if(!file_exists(ASSETS_PATH)) mkdir(ASSETS_PATH);

		/* Create a test folders for each of the fixture references */
		$fileIDs = $this->allFixtureIDs('Folder');
		foreach($fileIDs as $fileID) {
			$file = DataObject::get_by_id('Folder', $fileID);
			if(!file_exists(BASE_PATH."/$file->Filename")) mkdir(BASE_PATH."/$file->Filename");
		}
		
		/* Create a test files for each of the fixture references */
		$fileIDs = $this->allFixtureIDs('File');
		foreach($fileIDs as $fileID) {
			$file = DataObject::get_by_id('File', $fileID);
			$fh = fopen(BASE_PATH."/$file->Filename", "w");
			fwrite($fh, str_repeat('x',1000));
			fclose($fh);
		}
		// USERS:
		// 1 x ADMIN user
		// 1 x Member with SECUREFILEACCESS
		// 1 x Member with SECURE_FILE_SETTINGS	
		// 1 x Member
		
	}
	
	function tearDown() {
		/* Remove the test files that we've created */
		$fileIDs = $this->allFixtureIDs('File');
		foreach($fileIDs as $fileID) {
			$file = DataObject::get_by_id('File', $fileID);
			if(file_exists(BASE_PATH."/$file->Filename")) unlink(BASE_PATH."/$file->Filename");
		}

		/* Remove the test folders that we've crated */
		$fileIDs = array_reverse($this->allFixtureIDs('Folder'));
		foreach($fileIDs as $fileID) {
			$file = DataObject::get_by_id('Folder', $fileID);
			if(file_exists(BASE_PATH."/$file->Filename")) rmdir(BASE_PATH."/$file->Filename");
		}
		
		if(!in_array('MemberAuthenticator', $this->priorAuthenticators)) {
			Authenticator::unregister('MemberAuthenticator');
		}
		Authenticator::set_default_authenticator($this->priorDefaultAuthenticator);		
		
		parent::tearDown();
	}

	/**
	 * @todo Implement - make sure [un]setting security
	 * writes/deletes htaccess rules correctly. Test only
	 * ADMIN & SECURE_FILE_SETTINGS users can make these changes
	 */
	function testModifyFolderSecurity() {
		$secure_folder = $this->objFromFixture('Folder', '1');
		
		$this->assertFalse($this->checkHasHtaccess($secure_folder), 'New folder does not have htaccess rules');
		
		$secure_folder->Secured = true;
		$secure_folder->write();
		$this->assertTrue($this->checkHasHtaccess($secure_folder), 'Folder has correct htaccess rules after write');
		
		$secure_folder->Secured = false;
		$secure_folder->write();
		$this->assertFalse($this->checkHasHtaccess($secure_folder), 'Secure folder marked as unsecure removes htaccess');
	}
	
	/**
	 * @todo Implement - Test that unsecured files can be 
	 * accessed as normal (rational check)
	 */
	function testAccessToUnsecureFile() {
		// Ensure the expected response object is returned:
		SecureFileController::UseInternalSendFile();
		
		// Test access to unsecure file:
		$secure_file = $this->objFromFixture('File', 'file2');
		$response = Director::test($secure_file->AbsoluteURL);
		$this->assertEquals($response->getStatusCode(), '200', 'Unsecure files are accessible.');
		$this->assertEquals($response->getBody(), file_get_contents($secure_file->FullPath), 'Unsecure files pass body content exactly.');
	}	

	/**
	 * @todo Implement - Test that unauthorised users cannot
	 * access secure files and that the correct users can.
	 */
	function testAccessToSecuredFile() {
		// Ensure the expected response object is returned:
		SecureFileController::UseInternalSendFile();
		
		$secure_folder = $this->objFromFixture('Folder', '1');
		$secure_folder->Secured = true;
		$secure_folder->write();
		
		// Test access to secure file restricted:
		$secure_file = $this->objFromFixture('File', 'file1');
		$response = Director::test($secure_file->AbsoluteURL);
		$this->assertEquals($response->getStatusCode(), '302', 'Secure files force redirection to login form.');
		$this->assertFalse($response->isError(), 'Secure files return a valid response.');
		
		// Test access to secure file on subfolder restricted:
		$secure_file = $this->objFromFixture('File', 'file3');
		$response = Director::test($secure_file->AbsoluteURL);
		$this->assertEquals($response->getStatusCode(), '302', 'Secure files in child folder force redirection to login form.');
		$this->assertFalse($response->isError(), 'Secure filesin child folder return a valid response.');
		
		$secure_folder->Secured = false;
		$secure_folder->write();
	}
	
	function checkHasHtaccess($folder) {
		$htaccess_path = BASE_PATH."/{$folder->Filename}".SecureFileController::$htaccess_file;
		if(!file_exists($htaccess_path))
			return false;
		$content = file_get_contents($htaccess_path);
		return ($content == SecureFileController::htaccess_content()); 
	}
	

}
