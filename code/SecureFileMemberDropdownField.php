<?php
/**
 * A Member DropdownField class to get around TableField issues
 *
 * @package securefiles
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileMemberDropdownField extends DropdownField {

	function __construct($name, $title = null, $source = array(), $value = "", $form = null, $emptyString = null) {
		$options = DataObject::get("Member");

		$optionArray = array( '0' => '');

		if($options) foreach( $options as $option ) {
			$optionArray[$option->ID] = $option->Name;
		}

		parent::__construct( $name, $title, $optionArray, $value );
	}

}
?>