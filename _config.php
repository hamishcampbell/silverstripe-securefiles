<?php
DataObject::add_extension('File', 'SecureFileGroupPermissionDecorator');
DataObject::add_extension('File', 'SecureFileDecorator');

Director::addRules(50, array(ASSETS_DIR . '/$Action' => 'SecureFileController'));
?>