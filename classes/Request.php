<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * HTTP Request 데이터를 관리하는 클래스를 정의한다.
 *
 * @file /classes/Request.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2024. 11. 1.
 */
class Request
{
    /**
     * @var object $_configs 언어코드
     */
    private static array $_languages = [];

    /**
     * 현재 호스트를 가져온다.
     *
     * @return string $host
     */
    public static function host(): string
    {
        return isset($_SERVER['HTTP_HOST']) == true ? strtolower($_SERVER['HTTP_HOST']) : 'localhost';
    }

    /**
     * 현재 요청방식을 가져온다.
     *
     * @return string $method (GET, POST, PUT, DELETE, PATCH)
     */
    public static function method(): string
    {
        return Header::get('X-Method') ??
            (Header::get('Access-Control-Request-Method') ??
                (isset($_SERVER['REQUEST_METHOD']) == true ? $_SERVER['REQUEST_METHOD'] : 'GET'));
    }

    /**
     * 클라이언트 아이피를 가져온다.
     * Proxy 서버를 통해 접속하였을 경우에도 가급적 실제 아이피를 가져온다.
     *
     * @return string $ip
     */
    public static function ip(): string
    {
        return isset($_SERVER['HTTP_X_FORWARDED_FOR']) == true
            ? $_SERVER['HTTP_X_FORWARDED_FOR']
            : $_SERVER['REMOTE_ADDR'];
    }

    /**
     * 클라이언트 디바이스를 가져온다.
     *
     * @return string $device
     */
    public static function device(): string
    {
        return isset($_SERVER['HTTP_USER_AGENT']) == true ? $_SERVER['HTTP_USER_AGENT'] : '';
    }

    /**
     * 현재 URL을 가져온다.
     *
     * @param bool|array $query 쿼리스트링 포함 여부 (true : 전체, false : 포함하지 않음, array : 포함할 쿼리스트링)
     * @return string $url
     */
    public static function url(bool|array $query = true): string
    {
        $uri = explode('?', isset($_SERVER['REQUEST_URI']) == true ? $_SERVER['REQUEST_URI'] : '/');
        $url = $uri[0];
        $queryString = isset($uri[1]) == true ? '?' . $uri[1] : '';
        if (preg_match('/(&|\?)route=/', $queryString) == true) {
            if (is_bool($query) == true) {
                $query = [];
            }
            $query['route'] = Request::get('route');
        }

        if ($query !== false) {
            $url .= self::query($query === true ? [] : $query, '?');
        }

        return $url;
    }

    /**
     * GET 으로 전달되는 QUERY_STRING(URL의 ? 이하부분)중 일부 파라매터값을 변경하고, 비어있거나 불필요한 QUERY_STRING 삭제한다.
     *
     * @param string[] $replacements array('GET 파라매터 KEY'=>'변경할 값, 해당값이 NULL 인 경우 GET 파라매터를 지운다.')
     * @param bool|string $is_string 문자로 반환할지 여부 (true : 문자로 반환, false : 배열로 반환, bool 이 아닌 경우 해당 문자열을 앞에 포함하여 반환(예 : ?))
     * @return string|array $queryString 정리된 GET 파라매터
     */
    public static function query(array $replacements = [], bool|string $is_string = true): string|array
    {
        $uri = explode('?', isset($_SERVER['REQUEST_URI']) == true ? $_SERVER['REQUEST_URI'] : '/');
        $queryString = isset($uri[1]) == true ? $uri[1] : '';
        if (isset($replacements['route']) === false) {
            $replacements['route'] = null;
        }
        $queries = strlen($queryString) > 0 ? explode('&', $queryString) : [];

        $origins = [];
        foreach ($queries as $query) {
            list($key, $value) = explode('=', $query);
            $origins[$key] = $value;
        }

        $queryStrings = array_filter(array_merge($origins, $replacements));

        if ($is_string === false) {
            return $queryStrings;
        } else {
            $queryString = str_replace('%2F', '/', http_build_query($queryStrings, '', '&'));
            if ($is_string === true || strlen($queryString) === 0) {
                return $queryString;
            } else {
                return $is_string . $queryString;
            }
        }
    }

    /**
     * URL 과 QUERY_STRING 를 결합한다.
     *
     * @param string $url
     * @param string|array $queryString
     * @return string $url
     */
    public static function combine(string $url, string|array $queryString = ''): string
    {
        if (is_array($queryString) == true) {
            $queryString = http_build_query($queryString, '&');
        }

        if (strlen($queryString) == 0) {
            return $url;
        }

        return strpos($url, '?') !== false ? $url . '&' . $queryString : $url . '?' . $queryString;
    }

    /**
     * GET 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return string|array|null $value
     */
    public static function get(string $name, bool $is_required = false): string|array|null
    {
        $value = isset($_GET[$name]) == true ? $_GET[$name] : null;
        if ($value === null) {
            if ($is_required == true) {
                ErrorHandler::print(ErrorHandler::error('REQUIRED', $name));
            }
            return null;
        }

        if (is_string($value) == true) {
            $value = trim(Format::normalizer($value));
        } else {
            foreach ($value as &$var) {
                $var = trim(Format::normalizer($var));
            }
        }

        return $value;
    }

    /**
     * GET 변수데이터를 특정값으로 분리한 배열형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param string $seperator 분리자 (기본값 : ,)
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?string[] $value
     */
    public static function getSplit(string $name, string $seperator = ',', bool $is_required = false): ?array
    {
        $value = Request::get($name, $is_required);
        if ($value == null) {
            return null;
        }

        return explode($seperator, $value);
    }

    /**
     * GET 변수데이터를 JSON 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return mixed $value
     */
    public static function getJson(string $name, bool $is_required = false): mixed
    {
        $value = Request::get($name, $is_required);
        if ($value == null) {
            return null;
        }
        return json_decode($value);
    }

    /**
     * GET 변수데이터를 INT 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?int $value
     */
    public static function getInt(string $name, bool $is_required = false): ?int
    {
        $value = Request::get($name, $is_required);
        return $value === null || is_numeric($value) == false ? null : intval($value, 10);
    }

    /**
     * GET 변수데이터를 INT 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?int $value
     */
    public static function getFloat(string $name, bool $is_required = false): ?float
    {
        $value = Request::get($name, $is_required);
        return $value === null || is_numeric($value) == false ? null : floatval($value);
    }

    /**
     * POST 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return string|array|null $value
     */
    public static function post(string $name, bool $is_required = false): string|array|null
    {
        $value = isset($_POST[$name]) == true ? $_POST[$name] : null;
        if ($value === null) {
            if ($is_required == true) {
                ErrorHandler::print(ErrorHandler::error('REQUIRED', $name));
            }
            return null;
        }

        if (is_string($value) == true) {
            $value = trim(Format::normalizer($value));
        } else {
            foreach ($value as &$var) {
                $var = trim(Format::normalizer($var));
            }
        }

        return $value;
    }

    /**
     * POST 변수데이터를 특정값으로 분리한 배열형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param string $seperator 분리자 (기본값 : ,)
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?string[] $value
     */
    public static function postSplit(string $name, string $seperator = ',', bool $is_required = false): ?array
    {
        $value = Request::post($name, $is_required);
        if ($value == null) {
            return null;
        }

        return explode($seperator, $value);
    }

    /**
     * POST 변수데이터를 JSON 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return mixed $value
     */
    public static function postJson(string $name, bool $is_required = false): mixed
    {
        $value = Request::post($name, $is_required);
        if ($value == null) {
            return null;
        }
        return json_decode($value);
    }

    /**
     * POST 변수데이터를 INT 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?int $value
     */
    public static function postInt(string $name, bool $is_required = false): ?int
    {
        $value = Request::post($name, $is_required);
        return $value === null || is_numeric($value) == false ? null : intval($value, 10);
    }

    /**
     * POST 변수데이터를 INT 형식으로 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?int $value
     */
    public static function postFloat(string $name, bool $is_required = false): ?float
    {
        $value = Request::post($name, $is_required);
        return $value === null || is_numeric($value) == false ? null : floatval($value);
    }

    /**
     * REQUEST 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return string|array|null $value
     */
    public static function all(string $name, bool $is_required = false): string|array|null
    {
        $value = isset($_REQUEST[$name]) == true ? $_REQUEST[$name] : null;
        if ($value === null) {
            if ($is_required == true) {
                ErrorHandler::print(ErrorHandler::error('REQUIRED', $name));
            }
            return null;
        }

        if (is_string($value) == true) {
            $value = trim(Format::normalizer($value));
        } else {
            foreach ($value as &$var) {
                $var = trim(Format::normalizer($var));
            }
        }

        return $value;
    }

    /**
     * FILES 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @param bool $is_required 필수여부 (기본값 : false)
     * @return ?object $value
     */
    public static function file(string $name, bool $is_required = false): ?object
    {
        $value = isset($_FILES[$name]) == true ? $_FILES[$name] : null;
        if (
            $value === null ||
            isset($_FILES[$name]) == false ||
            strlen($_FILES[$name]['tmp_name']) == 0 ||
            is_file($_FILES[$name]['tmp_name']) == false
        ) {
            if ($is_required == true) {
                ErrorHandler::print(ErrorHandler::error('REQUIRED', $name));
            }
            return null;
        }

        $_FILES[$name]['name'] = Format::normalizer($_FILES[$name]['name']);

        return (object) $_FILES[$name];
    }

    /**
     * SESSION 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @return mixed $value
     */
    public static function session(string $name): mixed
    {
        $value = isset($_SESSION[$name]) == true ? $_SESSION[$name] : null;
        if ($value === null) {
            return null;
        }

        return $value;
    }

    /**
     * SESSION 값을 저장한다.
     *
     * @param string $name 변수명
     * @param mixed $value 저장할 값 (NULL 인 경우 세션을 삭제한다.)
     * @return bool $success
     */
    public static function setSession(string $name, mixed $value = null): bool
    {
        if (defined('IM_SESSION_STARTED') == false) {
            if (headers_sent() == true) {
                return false;
            } else {
                iModules::session_start();
            }
        }

        if ($value === null) {
            unset($_SESSION[$name]);
        } else {
            $_SESSION[$name] = $value;
        }

        return true;
    }

    /**
     * COOKIE 변수데이터를 가져온다.
     *
     * @param string $name 변수명
     * @return ?string $value
     */
    public static function cookie(string $name): ?string
    {
        $value = isset($_COOKIE[$name]) == true ? $_COOKIE[$name] : null;
        if ($value === null) {
            return null;
        }

        return $value;
    }

    /**
     * COOKIE를 저장한다.
     *
     * @param string $name 변수명
     * @param ?string $value 저장할 값 (NULL 인 경우 세션을 삭제한다.)
     * @param int $lifetime 쿠키만료일시 (기본 1시간=3600)
     * @return bool $success
     */
    public static function setCookie(string $name, ?string $value = null, int $lifetime = 3600): bool
    {
        if (headers_sent() == true) {
            return false;
        }

        $options = [
            'expires' => time() + $lifetime,
            'path' => '/',
            'domain' => Configs::get('session_domain'),
            'secure' => Request::isHttps() == true,
            'httponly' => true,
            'samesite' => 'None',
        ];

        if ($value === null) {
            setcookie($name, '', $options);
        } else {
            setcookie($name, $value, $options);
        }

        return true;
    }

    /**
     * HTTPS 접속여부를 확인한다.
     *
     * @return bool $isHttps
     */
    public static function isHttps(): bool
    {
        if (isset($_SERVER['HTTPS']) == true && $_SERVER['HTTPS'] == 'on') {
            return true;
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) == true && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https') {
            return true;
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_SSL']) == true && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on') {
            return true;
        }

        return false;
    }

    /**
     * 사용자 브라우져에서 설정된 모든 언어코드를 가져온다.
     *
     * @param bool $is_primary_only 최우선 언어코드 1개만 반환할지 여부
     * @return array|string $languages
     */
    public static function languages(bool $is_primary_only = false): array|string
    {
        if (count(self::$_languages) == 0) {
            $accept = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) == true ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : 'ko';
            $languages = explode(',', $accept);
            foreach ($languages as &$language) {
                $language = substr($language, 0, 2);
            }

            self::$_languages = array_unique($languages);

            // 기본언어는 한국어이므로, 언어코드목록에 한국어가 없는 경우 포함시킨다.
            if (in_array('ko', self::$_languages) == false) {
                self::$_languages[] = 'ko';
            }
        }

        return $is_primary_only == true ? self::$_languages[0] : self::$_languages;
    }

    /**
     * 디버깅을 위해 전달된 변수를 화면상에 출력한다.
     *
     * @param mixed $val
     */
    public static function debug(mixed $val): void
    {
        echo '<pre>';
        var_dump($val);
        echo '</pre>';
    }
}
