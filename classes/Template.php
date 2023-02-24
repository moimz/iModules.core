<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 테마 및 템플릿을 화면에 출력하기 위한 템플릿 엔진 클래스를 정의한다.
 *
 * @file /classes/Template.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2022. 12. 1.
 */
class Template
{
    /**
     * @var bool $_configs 템플릿 초기화여부
     */
    private bool $_init = false;

    /**
     * @var ?Component $_owner 템플릿 소유자 (NULL 인 경우 아이모듈 코어)
     */
    private ?Component $_owner = null;

    /**
     * @var Component $parent 템플릿을 처리할 부모클래스
     */
    private Component $_parent;

    /**
     * @var string $_path 템플릿경로
     */
    private string $_path;

    /**
     * @var string $_name 템플릿명 (템플릿 폴더명)
     */
    private string $_name;

    /**
     * @var object $_name 템플릿 패키지 정보 (package.json)
     */
    private object $_package;

    /**
     * @var ?object $_configs 템플릿 환경설정
     */
    private object $_configs;

    /**
     * @var mixed[] $_values 현재 템플릿에서 사용할 변수를 지정한다.
     */
    private array $_values = [];

    /**
     * 템플릿 클래스를 선언한다.
     *
     * @param Component $parent 템플릿을 처리할 부모클래스
     * @param object $template 템플릿정보
     */
    public function __construct(Component $parent, object $template)
    {
        $this->_parent = $parent;

        /**
         * 템플릿명이 경로를 포함할 경우, 해당 경로에서 템플릿을 정의하고,
         * 그렇지 않을 경우 템플릿을 처리할 부모클래스의 기본 템플릿 경로에서 템플릿을 정의한다.
         */
        if (strpos($template->name, '/') === 0) {
            /**
             * 템플릿명에서 템플릿 경로를 적절하게 계산한다.
             */
            $paths = explode('/', preg_replace('/^\//', '', $template->name));

            /**
             * 템플릿명
             */
            $this->_name = array_pop($paths);

            /**
             * 템플릿을 가진 테마명
             */
            $theme = array_pop($paths);

            /**
             * 템플릿을 가지고 있는 대상의 종류에 따라 템플릿 소유자를 정의한다.
             */
            if (count($paths) == 0) {
                $this->_owner = null;
                $this->_path = '';
            } else {
                switch (array_shift($paths)) {
                    case 'modules':
                        $this->_owner = Modules::get(implode('/', $paths));
                        break;
                }

                if ($this->_owner == null) {
                    // @todo 오류
                }

                $this->_path = $this->_owner->getBase();
            }

            $this->_path .= '/themes/' . $theme . '/modules/' . $this->_parent->getName();
        } else {
            $this->_owner = $parent;
            $this->_name = $template->name;
            $this->_path = $this->_parent->getBase() . '/templates';
        }
        $this->_path .= '/' . $this->_name;

        if (is_dir($this->getPath()) == false || is_file($this->getPath() . '/package.json') == false) {
            ErrorHandler::print($this->error('NOT_FOUND_TEMPLATE', $this->getPath()));
        }

        $package = $this->getPackage();
        if (isset($package->configs) == true) {
            $configs = $template->configs ?? new stdClass();

            $configKeys = [];
            foreach ($package->configs as $configKey => $configValue) {
                $configKeys[] = $configKey;
                $configs->$configKey = Configs::getConfigsDefaultValue($configValue, $configs->$configKey ?? null);
            }
        } else {
            $configs = new stdClass();
        }
        $this->_configs = $configs;
    }

    /**
     * 템플릿을 정의된 요소들을 초기화한다.
     */
    public function init(): void
    {
        if ($this->_init == true) {
            return;
        }

        /**
         * 템플릿을 설정되지 않은 경우 에러메시지를 반환한다.
         */
        if ($this->_isLoaded() === false) {
            ErrorHandler::print($this->error('NOT_INITIALIZED_TEMPLATE'));
        }

        /**
         * 템플릿의 package.json 에 styles 나 scripts 가 설정되어 있다면, 해당 파일을 불러온다.
         */
        $package = $this->getPackage();
        if (isset($package->styles) == true && is_array($package->styles) == true) {
            foreach ($package->styles as $style) {
                $style = preg_match('/^http(s)?:\/\//', $style) == true ? $style : $this->getDir() . $style;
                Html::style($style);
            }
        }

        if (isset($package->scripts) == true && is_array($package->scripts) == true) {
            foreach ($package->scripts as $script) {
                $script = preg_match('/^http(s)?:\/\//', $style) == true ? $script : $this->getDir() . $script;
                Html::script($script);
            }
        }

        $this->_init = true;
    }

    /**
     * 템플릿 설정이 정의되어 있는지 확인한다.
     *
     * @return bool $isLoaded
     */
    private function _isLoaded(): bool
    {
        return isset($this->_name) == true;
    }

    /**
     * 현재 템플릿명(템플릿 폴더명)를 가져온다.
     *
     * @return string $name
     */
    public function getName(): string
    {
        return $this->_name ?? 'undefined';
    }

    /**
     * 현재 템플릿의 절대경로를 가져온다.
     *
     * @return string $path
     */
    public function getPath(): string
    {
        return Configs::path() . $this->_path;
    }

    /**
     * 현재 템플릿의 상대경로를 가져온다.
     *
     * @return string $dir
     */
    public function getDir(): string
    {
        return Configs::dir() . $this->_path;
    }

    /**
     * 템플릿의 package.json 정보를 가져온다.
     *
     * @return object $package package.json 정보
     */
    public function getPackage(): object
    {
        if ($this->_isLoaded() === false) {
            return null;
        }
        if (isset($this->_package) == true) {
            return $this->_package;
        }
        $this->_package = json_decode(file_get_contents($this->getPath() . '/package.json'));
        return $this->_package;
    }

    /**
     * 템플릿의 환경설정을 가져온다.
     *
     * @param ?string $key 설정을 가져올 키값 (NULL인 경우 전체 환경설정을 가져온다.)
     * @return mixed $value 환경설정값
     */
    public function getConfigs(?string $key = null): mixed
    {
        if ($key === null) {
            return $this->_configs;
        }
        return $this->_configs->{$key} ?? null;
    }

    /**
     * 템플릿 파일에서 사용할 변수를 할당한다.
     *
     * @param string|array $name 변수명
     * @param mixed $value 변수데이터
     * @param bool $is_clone 복제여부
     * @return Template $this
     */
    public function assign(string|array $name, mixed $value = null, bool $is_clone = false): Template
    {
        if (is_array($name) == true) {
            foreach ($name as $key => $value) {
                $this->assign($key, $value, $is_clone);
            }
        } else {
            $this->_values[$name] = $is_clone == true ? clone $value : $value;
        }
        return $this;
    }

    /**
     * 템플릿 파일에서 이용할 수 있는 데이터를 정리한다.
     *
     * @return mixed[] $values 정리된 변수
     */
    function getValues(): array
    {
        $values = $this->_values;
        $values['me'] = &$this->_parent;
        $values['template'] = &$this;
        $values['route'] = Router::get();

        return $values;
    }

    /**
     * 콘텐츠 레이아웃을 가져온다.
     *
     * @param string $file PHP 확장자를 포함하지 않는 레이아웃 파일명
     * @param string $header(옵션) 컨텍스트 HTML 상단에 포함할 헤더 HTML
     * @param string $footer(옵션) 컨텍스트 HTML 하단에 포함할 푸더 HTML
     * @return string $html 컨텍스트 HTML
     */
    function getLayout(string $file, string $header = '', string $footer = ''): string
    {
        /**
         * 템플릿폴더에 파일이 없다면 에러메세지를 출력한다.
         */
        if (is_file($this->getPath() . '/' . $file . '.html') == false) {
            return ErrorHandler::get($this->error('NOT_FOUND_TEMPLATE_FILE', $this->getPath() . '/' . $file . '.html'));
        }

        $this->init();

        /**
         * todo: 이벤트를 발생시킨다.
         */

        /**
         * 템플릿파일에서 사용할 변수선언
         */
        extract($this->getValues());

        if (is_file($this->getPath() . '/' . $file . '.html') == true) {
            ob_start();
            include $this->getPath() . '/' . $file . '.html';
            $context = ob_get_clean();
        }

        /**
         * todo: 이벤트를 발생시킨다.
         */
        $html = Html::tag($header, $context, $footer);

        return $html;
    }

    /**
     * 템플릿 관련 에러를 처리한다.
     *
     * @param string $code 에러코드
     * @param ?string $message 에러메시지
     * @param ?object $details 에러와 관련된 추가정보
     * @return ErrorData $error
     */
    public function error(string $code, ?string $message = null, ?object $details = null): ErrorData
    {
        switch ($code) {
            case 'NOT_FOUND_TEMPLATE':
                $error = ErrorHandler::data();
                $error->prefix = ErrorHandler::getText('TEMPLATE_ERROR');
                $error->message = ErrorHandler::getText('NOT_FOUND_TEMPLATE');
                $error->suffix = $message;
                return $error;

            case 'NOT_FOUND_TEMPLATE_FILE':
                $error = ErrorHandler::data();
                $error->prefix = ErrorHandler::getText('TEMPLATE_ERROR');
                $error->message = ErrorHandler::getText('NOT_FOUND_TEMPLATE_FILE');
                $error->suffix = $message;
                return $error;

            default:
                return iModules::error($code, $message, $details);
        }
    }
}