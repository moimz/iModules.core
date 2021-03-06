<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 언어팩 클래스를 정의한다.
 *
 * @file /classes/Language.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2022. 7. 6.
 */
class Language {
	/**
	 * 언어팩이 저장될 객체
	 */
	private static array $_texts = [];
	
	/**
	 * 언어팩을 초기화한다.
	 *
	 * @param string $path 언어팩을 탐색할 경로
	 * @param array $codes 언어팩을 탐색할 언어코드
	 */
	public static function init(string $path,array $codes):void {
		if (is_dir(self::getPath($path)) == false) return;
		if (isset(self::$_texts[$path]) == true) return;
		
		self::$_texts[$path] = [];
		foreach ($codes as $code) {
			if (is_file(self::getPath($path).'/'.$code.'.json') == true) {
				self::$_texts[$path][$code] = json_decode(file_get_contents(self::getPath($path).'/'.$code.'.json'),JSON_OBJECT_AS_ARRAY);
			}
		}
	}
	
	/**
	 * 루트폴더를 포함한 언어팩 경로를 가져온다.
	 *
	 * @param string $path 언어팩을 탐색할 경로
	 * @return string $path 루트폴더를 포함한 언어팩 탐색 경로
	 */
	public static function getPath(string $path):string {
		return Config::path().($path == '/' ? '' : $path).'/languages';
	}
	
	/**
	 * 문자열 템플릿에서 치환자를 실제 데이터로 변환한다.
	 *
	 * @param string|array $text 문자열 템플릿
	 * @param ?array $placeHolder 치환될 데이터
	 * @return string $message 치환된 메시지
	 */
	public static function replacePlaceHolder(string|array $text,?array $placeHolder=null):string|array {
		if ($placeHolder === null) return $text;
		
		if (preg_match_all('/\$\{(.*?)\}/',$text,$matches,PREG_SET_ORDER) == true) {
			foreach ($matches as $match) {
				$text = str_replace($match[0],isset($placeHolder[$match[1]]) == true ? $placeHolder[$match[1]] : '',$text);
			}
		}
		
		return $text;
	}
	
	/**
	 * 언어팩을 불러온다.
	 *
	 * @param string $text 언어팩코드
	 * @param ?array $placeHolder 치환자
	 * @param ?array $paths 언어팩을 탐색할 경로 (우선순위가 가장높은 경로를 배열의 처음에 정의한다.)
	 * @param ?array $codes 언어팩을 탐색할 언어코드 (우선순위가 가장높은 경로를 배열의 처음에 정의한다.)
	 * @return array|string|null $message 치환된 메시지
	 */
	public static function getText(string $text,?array $placeHolder=null,?array $paths=null,?array $codes=null):string|array {
		$paths ??= ['/'];
		$codes ??= Config::languages();
		$keys = explode('/',$text);
		$string = null;
		foreach ($paths as $path) {
			if (isset(self::$_texts[$path]) == false) {
				self::init($path,$codes);
			}
			
			foreach ($codes as $code) {
				if (isset(self::$_texts[$path][$code]) == false) continue;
				
				$string = self::$_texts[$path][$code];
				foreach ($keys as $key) {
					if (isset($string[$key]) == false) {
						$string = null;
						break;
					}
					$string = $string[$key];
				}
				
				if ($string !== null) return self::replacePlaceHolder($string,$placeHolder);
			}
		}
		
		return $string === null ? $text : self::replacePlaceHolder($string,$placeHolder);
	}
}
?>