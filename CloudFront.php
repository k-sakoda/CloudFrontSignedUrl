<?php

class CloudFront {

	/**
	 * @var string
	 */
	protected $key_pair_id;

	/**
	 * @var string
	 */
	protected $private_key_file;

	/**
	 * __construct
	 *
	 * @param string $key_pair_id
	 * @param string $private_key_file
	 */
	public function __construct($key_pair_id, $private_key_file) {
		$this->key_pair_id = $key_pair_id;
		$this->private_key_file = $private_key_file;
	}

	/**
	 * rsa_sha1_sign
	 *
	 * .
	 *
	 * @param string $policy
	 * @return string
	 */
	private function rsa_sha1_sign($policy) {
		$signature = '';
		$private_key = file_get_contents($this->private_key_file);
		$private_key_id = openssl_get_privatekey($private_key);
		openssl_sign($policy, $signature, $private_key_id);
		openssl_free_key($private_key_id);
		return $signature;
	}

	/**
	 * url_safe_base64_encode
	 *
	 * .
	 *
	 * @param string $policy
	 * @return string
	 */
	private function url_safe_base64_encode($policy) {
		$encoded_policy = base64_encode($policy);
		return str_replace(array('+', '=', '/'), array('-', '_', '~'), $encoded_policy);
	}

	/**
	 * create_stream_name
	 *
	 * .
	 *
	 * @param string $video_path
	 * @param string $signature
	 * @param string|null $policy
	 * @param int|null $expires
	 * @return string
	 */
	private function create_stream_name($video_path, $signature, $policy = null, $expires = null) {
		$separator = strpos($video_path, '?') === FALSE ? '?' : '&';
		if ($policy) {
			$result = $video_path . $separator . 'Policy=' . $policy . '&Signature=' . $signature . '&Key-Pair-Id=' . $this->key_pair_id;
		} elseif ($expires) {
			$result = $video_path . $separator . 'Expires=' . $expires . '&Signature=' . $signature . '&Key-Pair-Id=' . $this->key_pair_id;
		} else {
			$result = null;
		}
		return str_replace('\n', '', $result);
	}

	/**
	 * encode_query_params
	 *
	 * .
	 *
	 * @param string $policy
	 * @return string
	 */
	private function encode_query_params($policy) {
		return str_replace(array('?', '=', '&'), array('%3F', '%3D', '%26'), $policy);
	}

	/**
	 * get_canned_policy_stream_name
	 *
	 * .
	 *
	 * @param string $video_path
	 * @param int $expires
	 * @param bool $encode_query_params
	 * @return string
	 */
	public function get_canned_policy_stream_name($video_path, $expires, $encode_query_params = false) {
		$policy = '{"Statement":[{"Resource":"' . $video_path . '","Condition":{"DateLessThan":{"AWS:EpochTime":' . $expires . '}}}]}';
		$signature = $this->rsa_sha1_sign($policy, $this->private_key_file);
		$encoded_signature = $this->url_safe_base64_encode($signature);
		$stream_name = $this->create_stream_name($video_path, $encoded_signature, null, $expires);
		if ($encode_query_params) {
			$stream_name = $this->encode_query_params($stream_name);
		}
		return $stream_name;
	}

	/**
	 * get_custom_policy_stream_name
	 *
	 * .
	 *
	 * @param string $video_path
	 * @param string $policy
	 * @param bool $encode_query_params
	 * @return string
	 */
	public function get_custom_policy_stream_name($video_path, $policy, $encode_query_params = false) {
		$encoded_policy = $this->url_safe_base64_encode($policy);
		$signature = $this->rsa_sha1_sign($policy, $this->private_key_file);
		$encoded_signature = $this->url_safe_base64_encode($signature);
		$stream_name = $this->create_stream_name($video_path, $encoded_signature, $encoded_policy);
		if ($encode_query_params) {
			$stream_name = $this->encode_query_params($stream_name);
		}
		return $stream_name;
	}

}
