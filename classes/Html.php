<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * HTML 출력을 위한 클래스를 정의한다.
 *
 * @file /classes/Html.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2024. 10. 22.
 */
class Html
{
    /**
     * @var string[] $_heads <HEAD> 태그내에 포함될 태그
     */
    private static array $_heads = [];

    /**
     * @var string[] $_scripts 호출되는 스크립트 우선순위
     */
    private static array $_scripts = [];

    /**
     * @var string[] $_styles 호출되는 스타일시트 우선순위
     */
    private static array $_styles = [];

    /**
     * @var string[][] $_listeners HTML 문서 이벤트리스너
     */
    private static array $_listeners = [];

    /**
     * @var string $_language HTML 문서 언어코드
     */
    private static string $_language = 'ko';

    /**
     * @var string $_type HTML 문서타입 (website, context, admin)
     */
    private static string $_type = 'website';

    /**
     * @var ?string $_title HTML 문서 제목
     */
    private static ?string $_title = null;

    /**
     * @var ?string $_description HTML 문서 설명
     */
    private static ?string $_description = null;

    /**
     * @var ?string $_keywords HTML 문서 키워드
     */
    private static ?string $_keywords = null;

    /**
     * @var ?\modules\attachment\dtos\Attachment $_image HTML 문서 이미지
     */
    private static ?\modules\attachment\dtos\Attachment $_image = null;

    /**
     * @var string $_robots <META NAME="ROBOTS"> 태그설정
     */
    private static string $_robots = 'all';

    /**
     * @var string $_viewport <META NAME="VIEWPORT"> 태그설정
     */
    private static string $_viewport = 'user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, width=device-width';

    /**
     * @var string $_canonical 페이지 고유주소
     */
    private static ?string $_canonical = null;

    /**
     * @var string[] $_attributes <BODY> 태그 속성값
     */
    private static array $_attributes = [];

    /**
     * @var bool[] $_fonts 불러올 웹폰트
     */
    private static array $_fonts = [];

    /**
     * HTML 엘리먼트를 생성한다.
     *
     * @param string $name 태그명
     * @param array $attributes 태그속성
     * @param string $content 태그콘텐츠
     * @return string $element 태그요소
     */
    public static function element(string $name, ?array $attributes = null, ?string $content = null): string
    {
        $element = '<';
        $element .= $name;
        if ($attributes !== null) {
            foreach ($attributes as $key => $value) {
                if ($value !== null) {
                    $element .= ' ' . $key . '="' . $value . '"';
                }
            }
        }
        $element .= '>';
        if ($content !== null) {
            $element .= $content;
        }
        if ($content !== null) {
            $element .= '</' . $name . '>';
        }

        return $element;
    }

    /**
     * <HEAD> 태그 내부의 요소를 추가한다.
     *
     * @param string $name 태그명
     * @param array $attributes 태그속성
     * @param int $priority 우선순위 (0 ~ 10, 우선순위가 낮을수록 먼저 출력된다.)
     * @param ?string $content 태그본문
     */
    public static function head(string $name, array $attributes, int $priority = 10, ?string $content = null): void
    {
        $priority = min(max(-1, $priority), 10);
        $element = self::element($name, $attributes, $content);

        self::_head($element, $priority + 100);
    }

    /**
     * <HEAD> 태그 내부의 요소를 우선순위 가중치에 따라 추가한다.
     *
     * @param string $element 태그요소
     * @param int $priority 우선순위
     */
    private static function _head(string $element, int $priority): void
    {
        self::$_heads[$element] = $priority;
    }

    /**
     * HTML 문서의 언어코드를 정의한다.
     *
     * @param string $langauge
     */
    public static function language(string $language): void
    {
        self::$_language = $language;
    }

    /**
     * HTML 문서종류를 정의한다.
     *
     * @param string $type (website, context, admin)
     */
    public static function type(string $type): void
    {
        self::$_type = $type;
    }

    /**
     * HTML 문서제목을 정의한다.
     *
     * @param string $title
     */
    public static function title(string $title): void
    {
        self::$_title = $title;
    }

    /**
     * HTML 문서설명을 정의한다.
     *
     * @param string $description
     */
    public static function description(string $description): void
    {
        self::$_description = addslashes(preg_replace('/(\r|\n)/', ' ', $description));
    }

    /**
     * HTML 키워드를 정의한다.
     *
     * @param ?string $keywords
     */
    public static function keywords(?string $keywords): void
    {
        self::$_keywords = addslashes(preg_replace('/(\r|\n)/', ' ', $keywords));
    }

    /**
     * 페이지 이미지를 정의한다.
     *
     * @param ?\modules\attachment\dtos\Attachment $image 이미지객체
     */
    public static function image(?\modules\attachment\dtos\Attachment $image): void
    {
        if ($image?->getType() == 'image') {
            self::$_image = $image;
        }
    }

    /**
     * 현재 페이지의 검색로봇 규칙을 설정한다.
     * SEO를 위해 사용된다.
     *
     * @see https://developers.google.com/search/reference/robots_meta_tag?hl=ko
     * @param string $robots
     * @return null
     */
    public static function robots(string $robots): void
    {
        self::$_robots = $robots;
    }

    /**
     * <META NAME="VIEWPORT"> 태그설정을 정의한다.
     *
     * @param string $viewport
     */
    public static function viewport(string $viewport): void
    {
        self::$_viewport = $viewport;
    }

    /**
     * 페이지 고유주소를 설정한다.
     *
     * @param string $canonical 고유주소
     * @param bool $is_replacement 이미 고유주소가 존재할 경우 해당 주소를 대치할지 여부
     */
    public static function canonical(?string $canonical, bool $is_replacement = true): void
    {
        if (self::$_canonical == null || $is_replacement == true) {
            self::$_canonical = $canonical;
        }
    }

    /**
     * 컬러모드를 지정한다.
     *
     * @param string $color 컬러모드 (light, dark, auto)
     */
    public static function color(string $color): void
    {
        self::body('data-color-scheme', $color, true);
    }

    /**
     * 자바스크립트 추가한다.
     *
     * @param string|array $path 자바스크립트 경로
     * @param int $priority 우선순위 (-1 ~ 10, 우선순위가 낮을수록 먼저 호출된다. -1 일 경우 해당 스크립트는 제거된다.)
     */
    public static function script(string|array $path, int $priority = 10): void
    {
        if (is_array($path) == true) {
            $paths = $path;
            foreach ($paths as $path) {
                self::script($path, $priority);
            }
        } else {
            $priority = min(max(-1, $priority), 10);
            if (strpos($path, '/caches') == false) {
                $path = Configs::dir() . $path;
            }

            if (isset(self::$_scripts[$path]) == false || self::$_scripts[$path] > -1) {
                self::$_scripts[$path] = $priority;
            }
        }
    }

    /**
     * 스타일시트를 추가한다.
     *
     * @param string|array $path 스타일시트 경로
     * @param int $priority 우선순위 (-1 ~ 10, 우선순위가 낮을수록 먼저 호출된다. -1 일 경우 해당 스크립트는 제거된다.)
     */
    public static function style(string|array $path, int $priority = 10): void
    {
        if (is_array($path) == true) {
            $paths = $path;
            foreach ($paths as $path) {
                self::style($path, $priority);
            }
        } else {
            $priority = min(max(-1, $priority), 10);

            /**
             * scss 파일인 경우 Cache 를 통해 css 파일로 컨버팅한다.
             */
            if (preg_match('/\.scss$/i', $path) == true) {
                $path = Cache::scss($path);
                if ($path == null) {
                    return;
                }
            }

            if (strpos($path, '/caches') == false) {
                $path = Configs::dir() . $path;
            }

            if (isset(self::$_styles[$path]) == false || self::$_styles[$path] > -1) {
                self::$_styles[$path] = $priority;
            }
        }
    }

    /**
     * HTML onReady 이벤트리스너를 등록한다.
     */
    public static function ready(string $listener): void
    {
        if (isset(self::$_listeners['ready']) == false) {
            self::$_listeners['ready'] = [];
        }

        self::$_listeners['ready'][] = $listener;
    }

    /**
     * <BODY> attribute 를 추가한다.
     *
     * @param string $attribute attribute 명 (class, style 등)
     * @param ?string $value attribute 값 (NULL 인 경우 빈 attribute 를 추가한다.)
     * @param ?bool $is_replacement 먼저 정의된 attribute 를 대치할지 여부
     */
    public static function body(string $attribute, ?string $value = null, ?bool $is_replacement = true): void
    {
        if ($is_replacement === true || isset(self::$_attributes[$attribute]) == false) {
            self::$_attributes[$attribute] = $value;
        }
    }

    /**
     * <BODY> 스크롤영역을 설정한다.
     *
     * @param bool|string $scrollable
     */
    public static function scroll(bool|string $scrollable): void
    {
        if ($scrollable === false) {
            self::$_attributes['data-scroll'] = 'false';
        } else {
            self::$_attributes['data-scroll'] = 'true';
            self::$_attributes['data-scroll-x'] = $scrollable === true || $scrollable == 'x' ? 'true' : 'false';
            self::$_attributes['data-scroll-y'] = $scrollable === true || $scrollable == 'y' ? 'true' : 'false';
        }
    }

    /**
     * 웹폰트를 불러온다.
     *
     * @param string $font 폰트명
     * @param bool $is_cache 캐시여부 (항상 사용되는 폰트가 이는 경우 캐시사용시 로드되지 않을 수 있음)
     */
    public static function font(string $font, bool $is_cache = false): void
    {
        if (isset(self::$_fonts[$font]) == false || self::$_fonts[$font] != $is_cache) {
            self::$_fonts[$font] = $is_cache;
        }
    }

    /**
     * 함수 매개변수로 들어온 모든 문자열을 줄바꿈하여 문자열로 반환한다.
     *
     * @param string ...$tags
     * @return string $html
     */
    public static function tag(string ...$tags): string
    {
        return implode("\n", array_filter($tags));
    }

    /**
     * 함수 매개변수로 들어온 모든 문자열을 줄바꿈하여 출력한다.
     *
     * @param string ...$tags
     * @return string $html
     */
    public static function print(string ...$tags): void
    {
        echo self::tag(...$tags);
    }

    /**
     * HTML 기본 헤더를 가져온다.
     *
     * @return string $header
     */
    public static function header(): string
    {
        $header = self::tag('<!DOCTYPE HTML>', '<html lang="' . self::$_language . '">', '<head>', '');

        /**
         * 기본 <HEAD> 태그요소를 추가한다.
         */
        self::_head(self::element('meta', ['charset' => 'utf-8']), 0);

        $title = self::$_title ?? 'iModules';
        self::_head(self::element('title', null, $title), 1);
        self::_head(self::element('meta', ['name' => 'description', 'content' => self::$_description]), 2);
        self::_head(self::element('meta', ['name' => 'keywords', 'content' => self::$_keywords]), 2);
        self::_head(self::element('meta', ['name' => 'viewport', 'content' => self::$_viewport]), 3);

        if (self::$_canonical != null) {
            self::_head(self::element('link', ['rel' => 'canonical', 'href' => self::$_canonical]), 4);
        }

        self::_head(self::element('meta', ['name' => 'robots', 'content' => self::$_robots]), 5);

        /**
         * OG 태그를 생성한다.
         */
        if (self::$_canonical != null) {
            self::_head(
                self::element('meta', [
                    'property' => 'og:url',
                    'content' => self::$_canonical ?? \Router::get()->getUrl(true, true),
                ]),
                6
            );
        }
        self::_head(
            self::element('meta', [
                'property' => 'og:title',
                'content' => self::$_title,
            ]),
            6
        );
        self::_head(
            self::element('meta', [
                'property' => 'og:description',
                'content' => self::$_description,
            ]),
            6
        );
        if (self::$_image !== null) {
            self::_head(
                self::element('meta', [
                    'property' => 'og:image',
                    'content' => self::$_image->getUrl('view', true),
                ]),
                6
            );
            self::_head(
                self::element('meta', [
                    'property' => 'og:image:width',
                    'content' => self::$_image->getWidth(),
                ]),
                6
            );
            self::_head(
                self::element('meta', [
                    'property' => 'og:image:height',
                    'content' => self::$_image->getHeight(),
                ]),
                6
            );
        }
        self::_head(
            self::element('meta', [
                'property' => 'twitter:card',
                'content' => 'summary_large_image',
            ]),
            6
        );

        /**
         * 웹폰트를 추가한다.
         */
        if (count(self::$_fonts) > 0) {
            foreach (self::$_fonts as $font => $is_cache) {
                if ($is_cache == true) {
                    Cache::style('font', '/fonts/' . $font . '.css');
                } else {
                    self::style('/fonts/' . $font . '.css');
                }
            }
            self::style(Cache::style('font'));
        }

        /**
         * 스크립트 경로를 <HEAD>에 추가한다.
         */
        foreach (self::$_scripts as $path => $priority) {
            if ($priority > 0) {
                self::_head(self::element('script', ['src' => $path . self::_time($path)], ''), 1000 + $priority);
            }
        }

        /**
         * 스타일시트 경로를 <HEAD>에 추가한다.
         */
        foreach (self::$_styles as $path => $priority) {
            if ($priority > 0) {
                self::_head(
                    self::element('link', [
                        'rel' => 'stylesheet',
                        'href' => $path . self::_time($path),
                        'type' => 'text/css',
                    ]),
                    2000 + $priority
                );
            }
        }

        /**
         * <HEAD> 요소를 우선순위에 따라 정렬한 뒤, $header 에 추가한다.
         */
        uasort(self::$_heads, function ($left, $right) {
            return $left <=> $right;
        });
        $header .= self::tag(...array_keys(self::$_heads));

        self::$_attributes['data-type'] = self::$_type;

        if (isset(self::$_attributes['data-dir']) == false) {
            self::$_attributes['data-dir'] = Configs::dir();
        }

        if (isset(self::$_attributes['data-rewrite']) == false) {
            self::$_attributes['data-rewrite'] =
                Configs::isInstalled() == true && Domains::has()?->isRewrite() == true ? 'true' : 'false';
        }

        if (isset(self::$_attributes['data-scrollbar']) == false) {
            self::$_attributes['data-scrollbar'] = 'auto';
        }

        $attributes = '';
        foreach (self::$_attributes as $key => $value) {
            $attributes .= ' ' . $key;
            if ($value !== null) {
                $attributes .= '="' . $value . '"';
            }
        }

        $header .= self::tag('', '</head>', '<body' . $attributes . '>');

        return $header;
    }

    /**
     * HTML 기본 푸터를 가져온다.
     *
     * @return string $footer
     */
    public static function footer(): string
    {
        $footer = '';
        if (isset(self::$_listeners['ready']) == true && count(self::$_listeners['ready']) > 0) {
            $footer .= self::tag(
                '<script>',
                'Html.ready(() => {',
                implode("\n", self::$_listeners['ready']),
                '});',
                '</script>'
            );
        }

        $footer .= self::tag('</body>', '</html>');

        return $footer;
    }

    /**
     * HTML 문자열로 부터 DOM 파서를 가져온다.
     *
     * @param string $html
     * @return \simplehtmldom\simplehtmldom\simple_html_dom $dom
     */
    public static function dom(string $html): \simplehtmldom\simplehtmldom\simple_html_dom
    {
        return new \simplehtmldom\simplehtmldom\simple_html_dom($html);
    }

    /**
     * 파일경로에 파일 수정시간을 추가한다.
     *
     * @param string $path 파일경로
     * @return string $time 추가되는 수정시간
     */
    private static function _time(string $path): string
    {
        $time = '';

        if (strpos($path, '//') !== 0 && strpos($path, 'http') !== 0) {
            if (is_file(Configs::dirToPath($path)) === false) {
                if (Configs::debug() == true) {
                    $time .= strpos($path, '?') === false ? '?t=' : '&t=';
                    $time .= time();
                }

                return $time;
            }
            if (strpos($path, 't=') !== false) {
                return $time;
            }
            $time .= strpos($path, '?') === false ? '?t=' : '&t=';
            $time .= Configs::debug() == true ? time() : filemtime(Configs::dirToPath($path));
        }

        return $time;
    }
}
