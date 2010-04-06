<?php
/**
 * Handles requests for secure files by url.
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileController extends Controller implements PermissionProvider {

	/**
	 * There are no publicly allowed actions on this controller.
	 * @var array
	 */
	public static $allowed_actions = array();
	
	/**
	 * @var string htaccess file as set by apache config
	 */
	static $htaccess_file = ".htaccess";

	/**
	 * Size of output chunks in kb while in PHP fread mode.
	 * @var integer
	 */
	static $chuck_size_kb = 32;
	
	/**
	 * Use X-Sendfile header mode instead of PHP fread mode.
	 * @var boolean
	 */
	protected static $use_x_sendfile = false;
	
	/**
	 * Use SilverStripe send file method. This is inefficient
	 * and is only provided for testing purposes.
	 * @var boolean
	 */
	protected static $use_ss_sendfile = false;
	
	/**
	 * Secure files htaccess rules
	 * 
	 * @return string
	 */	
	static function htaccess_content() {
		$rewrite = 
			"<IfModule xsendfile_module>\n" .
			"XSendFile on \n" . 
			"</IfModule>\n" .
			"RemoveHandler .php .phtml .php3 .php4 .php5 .inc \n" . 
			"RemoveType .php .phtml .php3 .php4 .php5 .inc \n" .
			"RewriteEngine On\n" .
			"RewriteBase " . (BASE_URL ? BASE_URL : "/") . "\n" . 
			"RewriteCond %{REQUEST_URI} ^(.*)$\n" .
			"RewriteRule (.*) " . SAPPHIRE_DIR . "/main.php?url=%1&%{QUERY_STRING} [L]\n";
		return $rewrite;
	}

	/**
	 * Use X-Sendfile headers to send files to the browser.
	 * This is quicker than pushing files through PHP but
	 * requires either Lighttpd or mod_xsendfile for Apache
	 * @link http://tn123.ath.cx/mod_xsendfile/ 
	 */
	static function use_x_sendfile_method() {
		self::use_default_sendfile_method();
		self::$use_x_sendfile = true;
	}

	/**
	 * Use internal SilverStripe to send files to the browser.
	 * This is the least efficient method but is useful for 
	 * testing. Not recommend for production
	 * environments.
	 */
	static function use_ss_sendfile_method() {
		self::use_default_sendfile_method();
		self::$use_ss_sendfile = true;
	}
	
	/**
	 * Use the default chucked file method to send files to the browser.
	 * This is the default method.
	 */
	static function use_default_sendfile_method() {
		self::$use_ss_sendfile = false;
		self::$use_x_sendfile = false;
	}
	
	/**
	 * Process incoming requests passed to this controller
	 * 
	 * @return HTTPResponse
	 */
	function handleAction() {
		$url = array_key_exists('url', $_GET) ? $_GET['url'] : $_SERVER['REQUEST_URI'];
		$file_path = Director::makeRelative($url);
		$file = File::find($file_path);
		
		if($file instanceof File) {
			return ($file->canView())
				? $this->fileFound($file, $file_path)
				: $this->fileNotAuthorized("Not Authorized");
		} else {
			return $this->fileNotFound("Not Found");
		}
	}
	
	/**
	 * File Not Found response
	 * 
	 * @param $body Optional message body
	 * @return HTTPResponse
	 */
	function fileNotFound($body = "") {
		if(ClassInfo::exists('SS_HTTPResponse')) {
			return new SS_HTTPResponse($body, 404);
		} else {
			return new HTTPResponse($body, 404);	
		}
	}
	
	/**
	 * File not authorized response
	 * 
	 * @param $body Optional message body
	 * @return HTTPResponse
	 */
	function fileNotAuthorized($body = "") {
		Security::permissionFailure($this, $body);
	}
	
	/**
	 * File found response
	 *
	 * @param $file File to send
	 * @param $alternate_path string If supplied, return the file from this path instead, for
	 * example, resampled images.
	 */
	function fileFound(File $file, $alternate_path = null) {

		// File properties
		$file_name = $file->Filename;
		$file_path = Director::getAbsFile($alternate_path ? $alternate_path : $file->FullPath);
		$file_size = filesize($file_path);
		
		// Testing mode - return an HTTPResponse
		if(self::$use_ss_sendfile) {
			if(ClassInfo::exists('SS_HTTPRequest')) {
				return SS_HTTPRequest::send_file(file_get_contents($file_path), $file_name);
			} else {
				return HTTPRequest::send_file(file_get_contents($file_path), $file_name);
			}
		}

		// Normal operation:
		$mimeType = HTTP::getMimeType($file_name);
		header("Content-Type: {$mimeType}; name=\"" . addslashes($file_name) . "\"");
		header("Content-Disposition: attachment; filename=" . addslashes($file_name));
		header("Content-Length: {$file_size}");
		header("Pragma: ");
		
		if(self::$use_x_sendfile) {
			session_write_close();
			header('X-Sendfile: '.$file_path);
			exit();			
		} elseif($filePointer = fopen($file_path, 'rb')) {
			session_write_close();
			ob_flush();
	   		flush();
	   		// Push the file while not EOF and connection exists
			while(!feof($filePointer) && !connection_aborted()) {
				print(fread($filePointer, 1024 * self::$chuck_size_kb));
				ob_flush();
	        	flush();
			}
			fclose($filePointer);
			exit();
		} else {
			// Edge case - either not found anymore or can't read
			return $this->fileNotFound();
		}
	}	
	
	/**
	 * Permission provider for access to secure files
	 * 
	 * @return array
	 */
	function providePermissions() {
		return array(
			'SECURE_FILE_ACCESS' => _t('SecureFiles.SECUREFILEACCESS', 'Access to Secured Files'),
			'SECURE_FILE_SETTINGS' => _t('SecureFiles.SECUREFILESETTINGS', 'Manage File Security Settings')
		);
	}

}
