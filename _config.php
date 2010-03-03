<?php
/**
 * Secure File Module Configuratoin
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell
 */

// CONTORLLER RULE, DO NOT MODIFY
Director::addRules(50, array(ASSETS_DIR . '/$Action' => 'SecureFileController'));
// -------------------------------


/**
 *  Apply optional permission methods here. Include them in the reverse
 *  order that you would like them to appear in the CMS.
 */
// DataObject::add_extension('File', 'SecureFileMemberPermissionDecorator');
// DataObject::add_extension('File', 'SecureFileGroupPermissionDecorator');

// BASE DECORATOR, DO NOT MODIFY
DataObject::add_extension('File', 'SecureFileDecorator');
// -------------------------------
