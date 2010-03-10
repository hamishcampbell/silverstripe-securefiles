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
class SecurityTest extends FunctionalTest {
	
	function setUp() {
		// Create a series of folders with different security permissoins, create users.
		// FOLDERS:
		// +- Unsecure
		// | +- Secure
		// +- Secure
		// 	 +- Child
		//     +- Child
		// USERS:
		// 1 x ADMIN user
		// 1 x Member with SECUREFILEACCESS
		// 1 x Member with SECURE_FILE_SETTINGS	
		// 1 x Member
		parent::setUp();
	}
	
	function tearDown() {
		// Revert setup changes
		parent::tearDown();
	}

	/**
	 * @todo Implement - make sure [un]setting security
	 * writes/deletes htaccess rules correctly. Test only
	 * ADMIN & SECURE_FILE_SETTINGS users can make these changes
	 */
	function testModifyFolderSecurity() {
		
	}
	
	/**
	 * @todo Implement - Test that unsecured files can be 
	 * accessed as normal (rational check)
	 */
	function testAccessToUnsecureFile() {
		
	}	

	/**
	 * @todo Implement - Test that unauthorised users cannot
	 * access secure files and that the correct users can.
	 */
	function testAccessToSecuredFile() {
		
	}
	

}
