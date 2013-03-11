<?php
/**
 * Secure Files Module Configuration
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell
 */
define('MODULE_SECUREFILES_PATH', basename(dirname(__FILE__)));

AssetAdmin::require_css(MODULE_SECUREFILES_PATH . '/css/SecureFiles.css');

/**
 * For large files or heavily trafficed sites use x-sendfile headers to by-pass
 * file handling in PHP. Supported in lighttpd and in Apache with mod_xsendfile
 * available at http://tn123.ath.cx/mod_xsendfile/
 */
// SecureFileController::use_x_sendfile_method();

/**
 * For testing or debug purposes, you can force this module to use the internal
 * frmaework send file method. Not recommended for production sites.
 */
// SecureFileController::use_ss_sendfile_method();
