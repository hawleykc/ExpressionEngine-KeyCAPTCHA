<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
* ExpressionEngine KeyCAPTCHA 
*
* Replaces the built-in CAPTCHA on member registration and comment forms
* Based on ExpressionEngine reCAPTCHA, by Brandon Jones (https://github.com/bhj/ExpressionEngine-reCAPTCHA)
* 
* @package		ExpressionEngine KeyCAPTCHA
* @author		Kellen Hawley
* @link			https://github.com/hawleykc/ExpressionEngine-KeyCAPTCHA
* @version		1.0.0
*/

class Keycaptcha_ext
{
	public $name			= 'KeyCAPTCHA';
	public $version			= '1.0.0';
	public $description		= "Replaces the built-in CAPTCHA on member registration and comment forms";
	public $settings_exist	= 'n';
	public $docs_url		= 'https://github.com/hawleykc/ExpressionEngine-KeyCAPTCHA';
	public $settings		= array();

	private $_error_msg;


	/**
	 *   Constructor
	 */	  
    function __construct($settings='')
    {
	    $this->EE =& get_instance();

        $this->settings = $settings;
    }


	/**
	 *   Create CAPTCHA
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function create_captcha()
	{
		// Bail out if settings are empty or wrong
		if ( ! $this->_validate_settings())
		{
			$this->EE->extensions->end_script = TRUE;

			return $this->_error_msg;
		}

		// Create our 'fake' entry in the captcha table
		$data = array(
			'date' 			=> time(),
			'ip_address'	=> $this->EE->input->ip_address(),
			'word'			=> 'KeyCAPTCHA'
		);

		$this->EE->db->insert('captcha', $data);// Stock keycaptcha PHP library (v4.0.0 as of this writing)

		// Use the keycaptcha lib to generate the js needed
		if (!class_exists('KeyCAPTCHA_CLASS')) {
			include('keycaptchalib/keycaptcha.php');
		}
		$kc_o = new KeyCAPTCHA_CLASS();
		$output = '<input type="hidden" name="capcode" id="capcode" value="false" />';
		$output .= $kc_o->render_js();

		$this->EE->extensions->end_script = TRUE;

		return $output;
	}


	/**
	 *   Validate CAPTCHA
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function validate_captcha()
	{
		// Bail out if settings are empty or wrong
		if ( ! $this->_validate_settings())
		{
			$this->EE->extensions->end_script = TRUE;

			return $this->_error_msg;
		}

		if (!class_exists('KeyCAPTCHA_CLASS')) {
			include('keycaptchalib/keycaptcha.php');
		}
		$kc_o = new KeyCAPTCHA_CLASS();


		// Check the answer
		if ($kc_o->check_result($_POST['capcode']))
		{
			// A visitor solved KeyCAPTCHA task correctly
			// Give EE what it's looking for
			$_POST['captcha'] = 'KeyCAPTCHA';
			return;
		}
		else
		{
			// A visitor solved KeyCAPTCHA task incorrectly
			// Ensure EE knows the captcha was invalid
			$_POST['captcha'] = '';

			// Whether the user's response was empty or just wrong, all we can do is make EE
			// think the captcha is missing, so we'll use more generic language for an error
			$this->EE->lang->loadfile('keycaptcha');
			$this->EE->lang->language['captcha_required'] = lang('keycaptcha_error');

			if ($this->settings['debug'] == 'y')
			{
				$this->EE->lang->language['captcha_required'] .= " ({$response->error})";
			}

			return;
		}


	}


	/**
	 *   Settings
	 *   Will hopefully eventually add these in here
	 *
	 * @access	public
	 * @param	void
	 * @return	array
	 */
	public function settings()
	{
		$settings = array(
			'user_id' 	=>  '',
			'private_key' 	=>  '',
			'debug'	=> array('r',
				array(
					'y' => lang('yes'),
					'n' => lang('no')
				),
				'n'
			)
		);

		return $settings;
	}


	/**
	 *   Settings sanity check and prep
	 *
	 * @access	private
	 * @param	void
	 * @return	bool
	 */
	private function _validate_settings()
	{
		// Have we been configured at all?
		if (count($this->settings) < 2)
		{
			$this->_error_msg = 'KeyCAPTCHA: Not yet configured';

			return FALSE;
		}

		// Be nice
		$this->settings['user_id'] = trim($this->settings['user_id']);
		$this->settings['private_key'] = trim($this->settings['private_key']);

		return TRUE;
	}

    
	/**
	 *   Activate extension
	 *
	 * @access	public
	 * @param	void
	 * @return	bool
	 */
	public function activate_extension()
	{
		$this->EE->db->insert('extensions',
			array(
				'class'        => __CLASS__,
				'method'       => 'create_captcha',
				'hook'         => 'create_captcha_start',
				'settings'     => '',
				'priority'     => 5,
				'version'      => $this->version,
				'enabled'      => 'y'
			)
		);

		$this->EE->db->insert('extensions',
			array(
				'class'        => __CLASS__,
				'method'       => 'validate_captcha',
				'hook'         => 'insert_comment_start',
				'settings'     => '',
				'priority'     => 1,
				'version'      => $this->version,
				'enabled'      => 'y'
			)
		);

		$this->EE->db->insert('extensions',
			array(
				'class'        => __CLASS__,
				'method'       => 'validate_captcha',
				'hook'         => 'member_member_register_start',
				'settings'     => '',
				'priority'     => 1,
				'version'      => $this->version,
				'enabled'      => 'y'
			)
		);

		// Support the Solspace User hook
		$this->EE->db->insert('extensions',
			array(
				'class'        => __CLASS__,
				'method'       => 'validate_captcha',
				'hook'         => 'user_register_start',
				'settings'     => '',
				'priority'     => 1,
				'version'      => $this->version,
				'enabled'      => 'y'
			)
		);

		// Support the Solspace Freeform hook
		$this->EE->db->insert('extensions',
			array(
				'class'        => __CLASS__,
				'method'       => 'validate_captcha',
				'hook'         => 'freeform_module_validate_end',
				'settings'     => '',
				'priority'     => 1,
				'version'      => $this->version,
				'enabled'      => 'y'
			)
		);
	}

	
	/**
	 *   Update extension
	 *
	 * @access	public
	 * @param	string
	 * @return	bool
	 */
	public function update_extension($current = '')
	{
		return TRUE;
	}


	/**
	 *   Disable extension
	 *
	 * @access	public
	 * @param	void
	 * @return	void
	 */
	public function disable_extension()
	{
		$this->EE->db->where('class', __CLASS__);
    	$this->EE->db->delete('extensions');
	}

}
// END CLASS

/* End of file ext.keycaptcha.php */
/* Location: ./system/expressionengine/third_party/keycaptcha/ext.keycaptcha.php */