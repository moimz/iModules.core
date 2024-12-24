<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * OAuth 클라이언트 인증을 위한 클래스를 정의한다.
 *
 * @file /classes/OAuthClient.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2024. 1. 26.
 */
class OAuthClient
{
    private string $_client_id;
    private string $_client_secret;

    private string $_access_type = 'offline';
    private string $_approval_prompt = 'auto';
    private ?string $_scope = null;

    private ?string $_token_url = null;

    private int $_refreshed_at = 0;

    /**
     * 클라이언트를 정의한다.
     *
     * @param string $client_id 클라이언트ID
     * @param string $client_secret 비밀키
     */
    public function __construct(string $client_id, string $client_secret)
    {
        $this->_client_id = $client_id;
        $this->_client_secret = $client_secret;
    }

    /**
     * OAuth 인증이 마무리되었을 때 이동할 URL 을 기록한다.
     *
     * @param ?string $redirect_url
     * @return OAuthClient $this
     */
    public function setRedirectUrl(?string $redirect_url, bool $replace = false): OAuthClient
    {
        if ($redirect_url === null) {
            return $this;
        }

        $url = parse_url($redirect_url);
        $replace = $replace == true && $url['host'] == Domains::get()->getHost();
        if (Request::session('OAUTH_REDIRECT') === null && $replace == true) {
            $_SESSION['OAUTH_REDIRECT'] = $redirect_url;
        }
        return $this;
    }

    /**
     * 엑세스타입을 설정한다.
     *
     * @param string $access_type 엑세스타입 (online, offline)
     * @return OAuthClient $this
     */
    public function setAccessType(string $access_type): OAuthClient
    {
        $this->_access_type = $access_type;

        return $this;
    }

    /**
     * 동의화면 표시여부를 설정한다.
     *
     * @param string $prompt 동의화면 표시여부 (none, consent, select_account)
     * @return OAuthClient $this
     */
    public function setApprovalPrompt($approval_prompt): OAuthClient
    {
        $this->_approval_prompt = $approval_prompt;
        return $this;
    }

    /**
     * 요청범위를 설정한다.
     *
     * @param ?string $scope 요청범위
     * @return OAuthClient $this
     */
    public function setScope(?string $scope = null): OAuthClient
    {
        $this->_scope = $scope;
        return $this;
    }

    /**
     * 인증 URL로 이동한다.
     *
     * @param string $auth_url 인증 URL
     */
    public function redirectAuthenticationUrl(string $auth_url): void
    {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->_client_id,
            'access_type' => $this->_access_type,
            'approval_prompt' => $this->_approval_prompt,
            'redirect_uri' => Domains::get()->getUrl() . Request::url(false),
        ];
        if ($this->_scope !== null && strlen($this->_scope) > 0) {
            //$params['scope'] = $this->_scope;
            $params['user_scope'] = $this->_scope;
        }

        $url = $auth_url . '?' . http_build_query($params, '', '&');

        Header::location($url);
    }

    /**
     * 인증코드를 이용하여 엑세스토큰을 가져온다.
     *
     * @param string $token_url 토큰발급 URL
     * @param string $code 인증코드
     * @return ?string $access_token
     */
    public function getAccessTokenByCode(string $token_url, string $code): ?string
    {
        $this->_token_url = $token_url;

        $params = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->_client_id,
            'client_secret' => $this->_client_secret,
            'code' => $code,
            'redirect_uri' => Domains::get()->getUrl() . Request::url(false),
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $results = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($info['http_code'] !== 200) {
            return null;
        }

        $results = json_decode($results ?? 'null');
        $results->access_token = $results->access_token ?? $results->authed_user->access_token;
        if ($results?->access_token ?? null !== null) {
            if ($results?->expires_in ?? null !== null) {
                $expired_at = time() + $results->expires_in;
            } else {
                $expired_at = 0;
            }
            $this->setAccessToken($results->access_token, $expired_at, $this->_scope);
        }

        if ($results?->refresh_token ?? null !== null) {
            $this->setRefreshToken($results->refresh_token);
        }

        return $results?->access_token ?? null;
    }

    /**
     * 인증코드를 이용하여 엑세스토큰을 가져온다.
     *
     * @return ?string $access_token
     */
    public function getAccessTokenByRefreshToken(): ?string
    {
        if ($this->isRefreshable() === false) {
            return null;
        }

        $this->_refreshed_at = time();

        $params = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->_client_id,
            'client_secret' => $this->_client_secret,
            'refresh_token' => $this->getRefreshToken(),
        ];

        print_r($params);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->_token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $results = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        echo '[getAccessTokenByRefreshToken]' .
            PHP_EOL .
            'ORIGIN : ' .
            $this->getAccessToken() .
            PHP_EOL .
            PHP_EOL .
            $info['http_code'] .
            PHP_EOL;

        $results = json_decode($results ?? 'null');
        print_r($results);

        if ($info['http_code'] !== 200) {
            return null;
        }

        if ($results?->access_token ?? null !== null) {
            if ($results?->expires_in ?? null !== null) {
                $expired_at = time() + $results->expires_in;
            } else {
                $expired_at = 0;
            }
            $this->setAccessToken($results->access_token, $expired_at, $this->_scope);
        }

        if ($results?->refresh_token ?? null !== null) {
            $this->setRefreshToken($results->refresh_token);
        }

        return $results?->access_token ?? null;
    }

    /**
     * JWT 토큰을 이용하여 엑세스토큰을 가져온다.
     *
     * @param string $token_url 토큰발급 URL
     * @param string $jwt JWT 토큰
     * @return ?string $access_token
     */
    public function getAccessTokenByJWT(string $token_url, string $jwt): ?string
    {
        echo $token_url . PHP_EOL;

        $params = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt,
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $results = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($info['http_code'] !== 200) {
            return null;
        }

        $results = json_decode($results ?? 'null');

        if ($results?->access_token ?? null !== null) {
            if ($results?->expires_in ?? null !== null) {
                $expired_at = time() + $results->expires_in;
            } else {
                $expired_at = 0;
            }
            $this->setAccessToken($results->access_token, $expired_at, $this->_scope);
        }

        if ($results?->refresh_token ?? null !== null) {
            $this->setRefreshToken($results->refresh_token);
        }

        return $results?->access_token ?? null;
    }

    /**
     * OAUTH 세션정보를 가져온다.
     *
     * @return ?object $session
     */
    public function getOAuthSession(): ?object
    {
        if (isset($this->_client_id) == false) {
            return null;
        }

        $sessions = Request::session('OAUTH_SESSIONS') ?? [];

        if (isset($sessions[$this->_client_id]) == false) {
            $sessions[$this->_client_id] = new stdClass();
            $sessions[$this->_client_id]->client_id = $this->_client_id;
            $sessions[$this->_client_id]->access_token = null;
            $sessions[$this->_client_id]->expired_at = 0;
            $sessions[$this->_client_id]->refresh_token = null;
            $sessions[$this->_client_id]->scope = null;

            $_SESSION['OAUTH_SESSIONS'] = $sessions;
        }

        return $sessions[$this->_client_id];
    }

    /**
     * OAUTH 세션정보를 저장한다.
     *
     * @param object $session 세션정보
     * @return OAuthClient $this
     */
    private function setOAuthSession(object $session): OAuthClient
    {
        $sessions = Request::session('OAUTH_SESSIONS') ?? [];

        $sessions[$this->_client_id] = $session;
        $_SESSION['OAUTH_SESSIONS'] = $sessions;

        return $this;
    }

    /**
     * 액세스토큰을 가져온다.
     *
     * @return string $access_token
     */
    public function getAccessToken(): ?string
    {
        $session = $this->getOAuthSession();
        $access_token = $session?->access_token ?? null;
        $expired_at = $session?->expired_at ?? 0;
        $scope = $session?->scope ?? null;

        if ($access_token === null || ($expired_at > 0 && $expired_at < time() - 30)) {
            if ($this->isRefreshable() === true) {
                $this->getAccessTokenByRefreshToken();
                return $this->getAccessToken();
            } else {
                return null;
            }
        }

        if ($this->_scope !== $scope) {
            return null;
        }

        return $access_token;
    }

    /**
     * 액세스토큰을 지정한다.
     *
     * @param ?string $access_token
     * @param int $expired_at 토큰만료시각
     * @param ?string $scope 토큰의 요청범위
     * @return OAuthClient $this
     */
    public function setAccessToken(?string $access_token, int $expired_at = 0, ?string $scope = null): OAuthClient
    {
        $session = $this->getOAuthSession();
        if ($session === null) {
            return $this;
        }

        $session->access_token = $access_token;
        $session->expired_at = $expired_at;
        $session->scope = $scope;
        $this->setOAuthSession($session);

        return $this;
    }

    /**
     * 현재 액세스토큰의 요청범위를 가져온다.
     *
     * @return ?string $scope
     */
    public function getAccessTokenScope(): ?string
    {
        return $this->getOAuthSession()?->scope ?? null;
    }

    /**
     * 현재 액세스토큰의 만료일시를 가져온다.
     *
     * @return int $expired_at
     */
    public function getAccessTokenExpiredAt(): int
    {
        return $this->getOAuthSession()?->expired_at ?? 0;
    }

    /**
     * 갱신토큰을 지정한다.
     *
     * @param ?string $refresh_token
     * @param ?string $token_url 갱신하기 위한 토큰 URL
     * @return OAuthClient $this
     */
    public function setRefreshToken(?string $refresh_token, ?string $token_url = null): OAuthClient
    {
        $this->_token_url ??= $token_url;
        $session = $this->getOAuthSession();
        if ($session === null) {
            return $this;
        }

        $session->refresh_token = $refresh_token;
        $this->setOAuthSession($session);

        return $this;
    }

    /**
     * 갱신토큰을 가져온다.
     *
     * @return string $access_token
     */
    public function getRefreshToken(): ?string
    {
        $session = $this->getOAuthSession();
        return $session?->refresh_token ?? null;
    }

    /**
     * 액세스토큰을 갱신할 수 있는지 확인한다.
     *
     * @return bool $refreshable
     */
    public function isRefreshable(): bool
    {
        if ($this->_refreshed_at < time() - 60 && $this->getRefreshToken() !== null && $this->_token_url !== null) {
            return true;
        }

        return false;
    }

    /**
     * get API 를 요청한다.
     *
     * @param string $url API 요청주소
     * @param array $params API 요청변수
     * @param array $headers API 요청시 사용할 추가 헤더 (Authorization 는 자동으로 추가됨)
     * @return mixed $results
     */
    public function get(string $url, array $params = [], array $headers = []): mixed
    {
        return $this->request('GET', $url, $params, $headers);
    }

    /**
     * post API 를 요청한다.
     *
     * @param string $url API 요청주소
     * @param array $params API 요청변수
     * @param array $headers API 요청시 사용할 추가 헤더
     * @return mixed $results
     */
    public function post(
        string $url,
        array $params = [],
        array $headers = ['Content-Type' => 'application/json']
    ): mixed {
        return $this->request('POST', $url, $params, $headers);
    }

    /**
     * API 를 요청한다.
     *
     * @param string $method API 요청방법
     * @param string $url API 요청주소
     * @param array $params API 요청변수
     * @param array $headers API 요청시 사용할 추가 헤더 (Authorization 는 자동으로 추가됨)
     * @return mixed $results
     */
    protected function request(string $method, string $url, array $params = [], array $headers = []): mixed
    {
        $method = strtoupper($method);
        $access_token = $this->getAccessToken();
        if ($access_token === null) {
            return false;
        }

        $headers['Authorization'] = 'Bearer ' . $access_token;

        $ch = curl_init();
        if (empty($headers) == false) {
            $httpHeaders = [];
            foreach ($headers as $key => $value) {
                $httpHeaders[] = $key . ': ' . $value;
            }

            curl_setopt($ch, CURLOPT_HTTPHEADER, $httpHeaders);
        }

        if ($method == 'POST') {
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            if (isset($headers['Content-Type']) && $headers['Content-Type'] === 'application/json') {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($params));
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
            }
        } else {
            if (empty($params) == true) {
                curl_setopt($ch, CURLOPT_URL, $url);
            } else {
                $url .= '?' . http_build_query($params);
                curl_setopt($ch, CURLOPT_URL, $url);
            }
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = explode(';', curl_getinfo($ch, CURLINFO_CONTENT_TYPE));
        $content_type = array_shift($content_type);

        curl_close($ch);
        //        echo $http_code;
        //        var_dump($this->isRefreshable());

        if ($http_code == 401 && $this->isRefreshable() == true) {
            $this->getAccessTokenByRefreshToken();
            return $this->request($method, $url, $params, $headers, true);
        }

        if ($content_type == 'application/json') {
            return json_decode($response);
        } else {
            return false;
        }
    }

    /**
     * JSON 객체로부터 특정 경로에 해당하는 값을 가져온다.
     *
     * @param object $json JSON 객체
     * @param string $path 가져올 경로
     * @return mixed $data
     */
    public function getJson(?object $json, string $path): mixed
    {
        $paths = explode('.', $path);
        $data = $json;

        while ($current = array_shift($paths)) {
            if ($data?->$current ?? null !== null) {
                $data = $data->$current;
            } else {
                return null;
            }
        }

        return $data;
    }

    /**
     * OAuth 인증이 시작된 URL 로 돌아간다.
     *
     * @param bool $is_redirect 주소로 이동할지 여부 (false 인 경우 이동할 경로를 반환한다.)
     */
    public function redirect(bool $is_redirect = true): string
    {
        $redirect =
            Request::session('OAUTH_REDIRECT') ??
            Sites::get()
                ->getIndex()
                ->getUrl();
        $_SESSION['OAUTH_REDIRECT'] = null;

        if ($is_redirect === true) {
            Header::location($redirect);
        }

        return $redirect;
    }

    /**
     * 현재 세션을 초기화한다.
     */
    public function clear(): void
    {
        $sessions = Request::session('OAUTH_SESSIONS') ?? [];
        if (isset($sessions[$this->_client_id]) == true) {
            unset($sessions[$this->_client_id]);
            $_SESSION['OAUTH_SESSIONS'] = $sessions;
        }
        $_SESSION['OAUTH_REDIRECT'] = null;
    }
}
