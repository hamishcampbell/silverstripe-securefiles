<?php
/**
 * Handles requests for secure files by url.
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileController extends Controller implements PermissionProvider {

	static $htaccessfile = ".htaccess";

	/**
	 * Secure files htaccess rules
	 */	
	static function HtaccessRules() {
		$rewrite = "RemoveHandler .php .phtml .php3 ,php4 .php5 .inc \n" . 
			"RemoveType .php .phtml .php3 .php4 .php5 .inc \n" .
			"RewriteEngine On\n";
		$rewrite .= "RewriteBase " . (BASE_URL ? BASE_URL : "/") . "\n;
		$rewrite .= "RewriteCond %{REQUEST_URI} ^(.*)$\n" .
			"RewriteRule (.*) " . SAPPHIRE_DIR . "/main.php?url=%1&%{QUERY_STRING} [L]\n";
		return $rewrite;
	}

	/**
	 * Process all incoming requests passed to this controller, checking
	 * that the file exists and passing the file data with MIME type if possible.
	 */
	function handleAction() {
		$canView = false;
		$memberID = Member::currentUserID();
		$url = array_key_exists('url', $_GET) ? $_GET['url'] : $_SERVER['REQUEST_URI'];
			
		// Secured folders cannot be accessed if not logged in
		if(!$memberID) return $this->FileNotAuthorized("Not Logged In");
		
		$file = File::find(Director::makeRelative($url));

		if($file instanceof File) {
			$folderID = $file->ParentID;
			while($folderID) {
				$query = new SQLQuery(
					"COUNT(`SecureFilePermission`.`ID`) as `Count`, " . 
					"SUM(`SecureFilePermission`.`SecureCanView`) as `CanView`, " . 
					"MAX(`File`.`ParentID`) as `ParentFileID`",
					"`SecureFilePermission` LEFT JOIN `File` on `SecureFilePermission`.`FileID` = `File`.`ID`",
					"`SecureFilePermission`.`FileID` = '{$folderID}' AND `SecureFilePermission`.`MemberID` = '{$memberID}'"
				);
				$result = $query->execute()->First();
								
				if($result['Count'] == 0) { // do nothing - no record for this folder
				} elseif($result['Count'] == $result['CanView']) { // can view this folder
					$canView = true;
				} else { // cannot view this folder, override previous settings, break!
					$canView = false;
					break;
				}
				$folderID = $result['ParentFileID'];
			}
				
			if(Permission::checkMember(Member::currentUser(), "SECURE_FILE_ACCESS")) return $this->FileFound($file);
			elseif($file->canView() && $canView) return $this->FileFound($file);
			else return $this->FileNotAuthorized("Not Authorized");
		} else {
			return $this->FileNotFound("Not Found");
		}
	}
	
	/**
	 * File not found response
	 */
	function FileNotFound($body = "") {
		return new HTTPResponse($body, 404);
	}
	
	/**
	 * File not authorized response
	 * @todo Could also return 404, not 403, to prevent directory trawling.
	 * This is permitted by rfc2616:
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.4
	 */
	function FileNotAuthorized($body = "") {
		Security::permissionFailure($this, $body);
	}
	
	/**
	 * File found response
	 * Returns the file in the body of the response with the appropriate
	 * content-type header
	 *
	 * @todo Should probably handle file system failures gracefully.
	 */
	function FileFound($file) {
		$response = new HTTPResponse();	
		$response->setStatusCode(200);
		$response->addHeader('Content-Type', self::MimeType($file->getFullPath()));
		$fp = @fopen($file->getFullPath(), "r");
		$response->setBody(@fread($fp, $file->getAbsoluteSize()));
		@fclose($fp);
		return $response;
	}	
	
	/**
	 * Permission provider for access to secure files
	 */
	function providePermissions() {
		return array(
			'SECURE_FILE_ACCESS' => _t('SecureFiles.SECUREFILEACCESS', 'Access to Secured Files'),
		);
	}

	/**
	 * Returns the MIME type for a particular file path.
	 * Adapted From http://php.net/manual/en/function.mime-content-type.php
	 */
	static function MimeType($filename) {

        $mime_types = array(

            'txt' => 'text/plain',
            'htm' => 'text/html',
            'html' => 'text/html',
            'php' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'xml' => 'application/xml',
            'swf' => 'application/x-shockwave-flash',
            'flv' => 'video/x-flv',

            // images
            'png' => 'image/png',
            'jpe' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'jpg' => 'image/jpeg',
            'gif' => 'image/gif',
            'bmp' => 'image/bmp',
            'ico' => 'image/vnd.microsoft.icon',
            'tiff' => 'image/tiff',
            'tif' => 'image/tiff',
            'svg' => 'image/svg+xml',
            'svgz' => 'image/svg+xml',

            // archives
            'zip' => 'application/zip',
            'rar' => 'application/x-rar-compressed',
            'exe' => 'application/x-msdownload',
            'msi' => 'application/x-msdownload',
            'cab' => 'application/vnd.ms-cab-compressed',

            // audio/video
            'mp3' => 'audio/mpeg',
            'qt' => 'video/quicktime',
            'mov' => 'video/quicktime',

            // adobe
            'pdf' => 'application/pdf',
            'psd' => 'image/vnd.adobe.photoshop',
            'ai' => 'application/postscript',
            'eps' => 'application/postscript',
            'ps' => 'application/postscript',

            // ms office
            'doc' => 'application/msword',
            'rtf' => 'application/rtf',
            'xls' => 'application/vnd.ms-excel',
            'ppt' => 'application/vnd.ms-powerpoint',

            // open office
            'odt' => 'application/vnd.oasis.opendocument.text',
            'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
        );

		if (function_exists('finfo_open')) {
			// (PHP >= 5.3.0, PECL fileinfo >= 0.1.0)
            $finfo = finfo_open(FILEINFO_MIME);
            $mimetype = finfo_file($finfo, $filename);
            finfo_close($finfo);
            return $mimetype;
		} elseif(function_exists('mime_content_type')) {
			// (PHP 4 >= 4.3.0, PHP 5)
			return mime_content_type($filename);
		} else {
			// Otherwise:
			$ext = strtolower(array_pop(explode('.',$filename)));
			if (array_key_exists($ext, $mime_types)) {
	            return $mime_types[$ext];
	        } else {
    	        return 'application/octet-stream';
			}
        }
    }
}
?>
