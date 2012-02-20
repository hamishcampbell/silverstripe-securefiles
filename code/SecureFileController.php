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
	 * @var array Disallow all public actions on this controller
	 */
	public static $allowed_actions = array();
	
	/**
	 * @var string htaccess file as set by apache config
	 */
	protected static $htaccess_file = ".htaccess";
	
	/**
	 * @var integer Size of output chunks in kb while in PHP fread mode.
	 */
	protected static $chunck_size_kb = 32;
	
	/**
	 * @var boolean Flag use X-Sendfile header mode instead of PHP fread mode.
	 */
	protected static $use_x_sendfile = false;
	
	/**
	 * @var boolean Flag use SilverStripe send file method.
	 */
	protected static $use_ss_sendfile = false;
	
	/**
	 * @var array i18n data for not authorized message as passed to _t
	 */
	protected static $i18n_not_authorized = array('SecureFiles.NOTAUTHORIZED', 'Not Authorized');
	
	/**
	 * @var array i18n data for not found message as passed to _t
	 */
	protected static $i18n_not_found = array('SecureFiles.NOTFOUND', 'Not Found');
	
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
	 * Use the default chuncked file method to send files to the browser.
	 * This is the default method.
	 */
	static function use_default_sendfile_method() {
		self::$use_ss_sendfile = false;
		self::$use_x_sendfile = false;
	}
	
	/**
	 * Set the size of upload chunk in bytes.
	 * @param int $kilobytes
	 */
	static function set_chunk_size($kilobytes) {
		$kilobytes = max(0, (int)$kilobytes);
		if(!$kilobytes) user_error("Invalid download chunk size", E_USER_ERROR);
		self::$chunck_size_kb = $kilobytes;
	}
	
	/**
	 * Set the Apache access file name (.htaccess by default)
	 * as determined by the AccessFileName Apache directive.
	 * @param string $filename
	 */
	static function set_access_filename($filename) {
		self::$htaccess_file = $filename;
	}
	
	/**
	 * Get the Apache access file name
	 * @return string
	 */
	static function get_access_filename() {
		return self::$htaccess_file;
	}
	
	/**
	 * Set a 'not authorized' message to replace the standard string
	 * @param $message HTML body of 401 Not Authorized response
	 * @param $i18n Reference to i18n path
	 */
	static function set_not_authorized_text($message = "Not Authorized", $i18n = "SecureFiles.NOTAUTHORIZED") {
		self::$i18n_not_authorized = array($i18n, $message);
	}
	
	/**
	 * Set a 'not found' message to replace the standard string
	 * @param $message HTML body of 404 Not Found response
	 * @param $i18n Reference to i18n path
	 */
	static function set_not_found_text($message = "Not Found", $i18n = "SecureFiles.NOTFOUND") {
		self::$i18n_not_found = array($i18n, $message);
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
			if ($file->canView()) {
				$file->extend('onAccessGranted');
				return $this->fileFound($file, $file_path);
			} else {
				$file->extend('onAccessDenied');
				return $this->fileNotAuthorized(call_user_func_array('_t', self::$i18n_not_authorized));
			}
		} else {
			return $this->fileNotFound(call_user_func_array('_t', self::$i18n_not_found));
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
		$file_name = $file->Name;
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
		header("Cache-Control: max-age=1, private");
		header("Content-Length: {$file_size}");
		header("Pragma: ");
		
		if(self::$use_x_sendfile) {
			session_write_close();
			header('X-Sendfile: '.$file_path);
			exit();
		} elseif($filePointer = @fopen($file_path, 'rb')) {
			session_write_close();
			$this->flush();
			// Push the file while not EOF and connection exists
			while(!feof($filePointer) && !connection_aborted()) {
				print(fread($filePointer, 1024 * self::$chunck_size_kb));
				$this->flush();
			}
			fclose($filePointer);
			exit();
		} else {
			// Edge case - either not found anymore or can't read
			return $this->fileNotFound();
		}
	}
	
	/**
	 * Flush the output buffer to the server (if possible).
	 * @see http://nz.php.net/manual/en/function.flush.php#93531
	 */
	function flush() {
		if(ob_get_length()) {
			@ob_flush();
			@flush();
			@ob_end_flush();
		}
		@ob_start();
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