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
	 * Size limit (bytes) before using alternative file
	 * send technique. Defaults to 50 kb.
	 * @var int 
	 */
	static $file_size_break_limit = 51200;
	
	/**
	 * Secure files htaccess rules
	 * 
	 * @return string
	 */	
	static function HtaccessRules() {
		$rewrite = 
			"RemoveHandler .php .phtml .php3 ,php4 .php5 .inc \n" . 
			"RemoveType .php .phtml .php3 .php4 .php5 .inc \n" .
			"RewriteEngine On\n" .
			"RewriteBase " . (BASE_URL ? BASE_URL : "/") . "\n" . 
			"RewriteCond %{REQUEST_URI} ^(.*)$\n" .
			"RewriteRule (.*) " . SAPPHIRE_DIR . "/main.php?url=%1&%{QUERY_STRING} [L]\n";
		return $rewrite;
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
	 * @see HTTPRequest::send_file()
	 * @todo clean up
	 */
	function FileFound($file) {
		if($file->getAbsoluteSize() > self::$file_size_break_limit) {
			$mimeType = HTTP::getMimeType($file->Filename);
			header("Content-Type: {$mimeType}; name=\"" . addslashes($file->Filename) . "\"");
			header("Content-Disposition: attachment; filename=" . addslashes($file->Filename));
			header("Content-Length: {$file->getAbsoluteSize()}");
			header("Pragma: ");
			
			session_write_close();
			
			if($file = fopen($file->getFullPath(), 'rb')) {
				while(!feof($file) && !connection_aborted()) {
					print(fread($file, 1024*8));
					ob_flush();
            		flush();
				}
				fclose($file);
			}
			exit();			
		} else {
			if(ClassInfo::exists('SS_HTTPRequest')) {
				// >= 2.4
				return SS_HTTPRequest::send_file(file_get_contents($file->FullPath), $file->Filename);
			} else {
				// < 2.4
				return HTTPRequest::send_file(file_get_contents($file->FullPath), $file->Filename);	
			}
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
