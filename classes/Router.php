<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 요청된 주소에 따른 경로를 처리한다.
 *
 * @file /classes/Router.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2022. 12. 1.
 */
class Router
{
    /**
     * @var string $_path 현재경로
     */
    private static string $_path;

    /**
     * @var string $_path 현재경로의 언어코드
     */
    private static string $_language;

    /**
     * @var Route[] $_routes 지정된 전체경로
     */
    private static array $_routes = [];

    /**
     * 현재 경로를 초기화한다.
     */
    public static function init(): void
    {
        if (isset(self::$_path) == true) {
            return;
        }

        $domain = Domains::get();
        $routes = self::stringToArray(Request::get('route') ?? '');
        if ($domain->isInternationalization() == true) {
            if (count($routes) > 0 && preg_match('/^[a-z]{2}$/i', $routes[0]) == true) {
                $code = array_shift($routes);
                self::$_language = $code;
            } else {
                self::$_language = $domain->getLanguage();
            }
        }

        self::$_path = '/' . implode('/', $routes);
    }

    /**
     * 현재 사이트에 경로를 추가한다.
     *
     * @param string $path 경로
     * @param string $language 언어코드 (* : 모든 언어, @ : 현재 사이트 언어, # : 언어 구분 없음)
     * @param string $type 종류(context, html, json, blob)
     * @param callable|Context $closure
     */
    public static function add(string $path, string $language, string $type, callable $closure): void
    {
        switch ($language) {
            /**
             * 도메인 전체 언어에 대하여 경로를 추가한다.
             */
            case '*':
                foreach (Domains::get()->getLanguages() as $language) {
                    self::$_routes['/' . $language . $path] = new Route($path, $language, $type, $closure);
                }
                break;

            /**
             * 언어구분 없이 경로를 추가한다.
             */
            case '#':
                self::$_routes[$path] = new Route($path, $language, $type, $closure);
                break;

            /**
             * 현재 사이트 언어에 경로를 추가한다.
             */
            case '@':
                $language = Sites::get()->getLanguage();

            default:
                self::$_routes['/' . $language . $path] = new Route($path, $language, $type, $closure);
        }
    }

    /**
     * 현재 경로에 해당하는 객체를 가져온다.
     *
     * @return Route $route
     */
    public static function get(): Route
    {
        $paths = array_keys(self::$_routes);
        foreach ($paths as $path) {
            $matcher = str_replace('/', '\/', $path);
            $matcher = str_replace('*', '(.*?)', $matcher);
            $matcher = preg_replace('/{[^}]+}/', '(.*?)', $matcher);

            if (
                preg_match('/^' . $matcher . '$/', self::getPath(), $matches) == true ||
                preg_match('/^' . $matcher . '$/', '/' . self::getLanguage() . self::getPath(), $matches) == true
            ) {
                return self::$_routes[$path];
            }
        }

        ErrorHandler::print(self::error('NOT_FOUND_URL'));
    }

    /**
     * 현재 경로를 가져온다.
     *
     * @return string $language
     */
    public static function getPath(): string
    {
        Router::init();
        return self::$_path;
    }

    /**
     * 현재 언어코드를 가져온다.
     *
     * @return string $language
     */
    public static function getLanguage(): string
    {
        Router::init();
        return self::$_language;
    }

    /**
     * 경로문자열을 경로배열로 변경한다.
     *
     * @param string $path
     * @return string[] $path
     */
    public static function stringToArray(string $route): array
    {
        $route = preg_replace('/^\/?(.*?)(\/)?$/', '\1', $route);
        return $route ? explode('/', $route) : [];
    }

    /**
     * 경로 관련 에러를 처리한다.
     *
     * @param string $code 에러코드
     * @param ?string $message 에러메시지
     * @param ?object $details 에러와 관련된 추가정보
     * @return ErrorData $error
     */
    public static function error(string $code, ?string $message = null, ?object $details = null): ErrorData
    {
        switch ($code) {
            case 'NOT_FOUND_CONTEXT':
                $error = ErrorHandler::data();
                $error->message = ErrorHandler::getText($code);
                $error->suffix = $message;
                $error->stacktrace = ErrorHandler::trace('Contexts');
                return $error;

            case 'NOT_FOUND_URL':
                $error = ErrorHandler::data();
                $error->message = ErrorHandler::getText($code);
                $error->suffix = Request::url();
                return $error;

            default:
                return iModules::error($code, $message, $details);
        }
    }
}