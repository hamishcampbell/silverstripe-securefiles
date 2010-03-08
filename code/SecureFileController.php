<?php
/**
 * Handles requests for secure files by url.
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileController extends Controller implements PermissionProvider {

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
	 * Secure files htaccess rules
	 * 
	 * @return string
	 */	
	static function HtaccessRules() {
		$rewrite = 
			"<IfModule xsendfile_module>\n" .
			"XSendFile on \n" . 
			"</IfModule>\n" .
			"RemoveHandler .php .phtml .php3 ,php4 .php5 .inc \n" . 
			"RemoveType .php .phtml .php3 .php4 .php5 .inc \n" .
			"RewriteEngine On\n" .
			"RewriteBase " . (BASE_URL ? BASE_URL : "/") . "\n" . 
			"RewriteCond %{REQUEST_URI} ^(.*)$\n" .
			"RewriteRule (.*) " . SAPPHIRE_DIR . "/main.php?url=%1&%{QUERY_STRING} [L]\n";
		return $rewrite;
	}

	/**
	 * Tell Secure Files to use X-Sendfile headers.
	 * This is quicker than pushing files through PHP but
	 * requires either Lighttpd or mod_xsendfile for Apache
	 * @link http://tn123.ath.cx/mod_xsendfile/ 
	 * @param boolean $value
	 */
	static function UseXSendFile($value) {
		self::$use_x_sendfile = (bool)$value;
	}
		
	/**
	 * Process incoming requests passed to this controller
	 * 
	 * @return HTTPResponse
	 */
	function handleAction() {
		$url = array_key_exists('url', $_GET) ? $_GET['url'] : $_SERVER['REQUEST_URI'];
		$file = File::find(Director::makeRelative($url));
		if($file instanceof File) {
			return ($file->canView())
				? $this->FileFound($file)
				: $this->FileNotAuthorized("Not Authorized");
		} else {
			return $this->FileNotFound("Not Found");
		}
	}
	
	/**
	 * File Not Found response
	 * 
	 * @param $body Optional message body
	 * @return HTTPResponse
	 */
	function FileNotFound($body = "") {
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
	function FileNotAuthorized($body = "") {
		Security::permissionFailure($this, $body);
	}
	
	/**
	 * File found response
	 *
	 * @param $file File to send
	 */
	function FileFound(File $file) {

		$mimeType = HTTP::getMimeType($file->Filename);
		header("Content-Type: {$mimeType}; name=\"" . addslashes($file->Filename) . "\"");
		header("Content-Disposition: attachment; filename=" . addslashes($file->Filename));
		header("Content-Length: {$file->getAbsoluteSize()}");
		header("Pragma: ");
		
		if(self::$use_x_sendfile) {
			session_write_close();
			header('X-Sendfile: '.$file->Filename);
			exit();			
		} elseif($filePointer = fopen($file->getFullPath(), 'rb')) {
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
			return $this->FileNotFound();
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
