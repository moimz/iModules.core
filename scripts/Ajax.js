/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 관리자모듈에서 사용되는 비동기호출 클래스를 정의한다.
 *
 * @file /scripts/Ajax.ts
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2024. 10. 9.
 */
class Ajax {
    static errorHandler = null;
    static fetchs = new Map();
    /**
     * Fetch 요청의 UUID 값을 생성한다.
     *
     * @param {string} method - 요청방식
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {Ajax.Data|FormData} data - 전송할 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {string} uuid
     */
    static #uuid(method = 'GET', url, params = {}, data = {}, is_retry = true) {
        let postData = {};
        if (data instanceof FormData) {
            data.forEach((value, key) => {
                if (value instanceof File) {
                    postData[key] = value.name;
                }
                else {
                    postData[key] = value;
                }
            });
        }
        else {
            postData = data;
        }
        return Format.sha1(JSON.stringify({ method: method, url: url, params: params, data: postData, is_retry: is_retry }));
    }
    /**
     * 짧은시간내에 동일한 Fetch 요청이 될 경우,
     * 제일 처음 요청된 Fetch 만 수행하고 응답된 데이터를 다른 중복요청한 곳으로 반환한다.
     *
     * @param {string} method - 요청방식
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {Ajax.Data|FormData} data - 전송할 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} promise - 동일한 요청의 제일 첫번째 요청
     */
    static async #call(method = 'GET', url, params = {}, data = {}, is_retry = true) {
        const uuid = Ajax.#uuid(method, url, params, data, is_retry);
        if (Ajax.fetchs.has(uuid) == true) {
            return Ajax.fetchs.get(uuid);
        }
        Ajax.fetchs.set(uuid, Ajax.#fetch(method, url, params, data, is_retry));
        return Ajax.fetchs.get(uuid);
    }
    /**
     * 실제 Fetch 함수를 실행한다.
     *
     * @param {string} method - 요청방식
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {Ajax.Data|FormData} data - 전송할 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async #fetch(method = 'GET', url, params = {}, data = {}, is_retry = true) {
        const uuid = Ajax.#uuid(method, url, params, data, is_retry);
        const requestUrl = new URL(url, location.origin);
        for (const name in params) {
            if (params[name] === null) {
                requestUrl.searchParams.delete(name);
            }
            else {
                requestUrl.searchParams.append(name, params[name].toString());
            }
        }
        url = requestUrl.toString();
        let retry = (is_retry === false ? 10 : is_retry);
        const headers = {
            'X-Method': method,
            'Accept-Language': iModules.getLanguage(),
            'Accept': 'application/json',
        };
        let body = null;
        if (method == 'POST' || method == 'PUT' || method == 'PATCH') {
            if (data instanceof FormData) {
                body = data;
            }
            else {
                headers['Content-Type'] = 'application/json; charset=utf-8';
                body = JSON.stringify(data);
            }
        }
        if (method == 'SYNC') {
            method = 'GET';
        }
        try {
            const response = (await fetch(url, {
                method: method,
                headers: headers,
                body: body,
                cache: 'no-store',
                redirect: 'follow',
            }).catch(async (e) => {
                throw new Error(e);
            }));
            const results = (await response.json());
            if (results.success == false) {
                if (typeof Ajax.errorHandler == 'function') {
                    if (results.errors === undefined || results.message !== undefined) {
                        await Ajax.errorHandler(results);
                    }
                }
                else {
                    console.error(results);
                }
            }
            Ajax.fetchs.delete(uuid);
            return results;
        }
        catch (e) {
            Ajax.fetchs.delete(uuid);
            if (retry <= 3) {
                await iModules.sleep(1000);
                return Ajax.#call(method, url, params, data, ++retry);
            }
            else {
                if (typeof Ajax.errorHandler == 'function') {
                    await Ajax.errorHandler(e);
                }
                return { success: false };
            }
        }
    }
    /**
     * GET 방식으로 데이터를 가져온다.
     *
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async get(url, params = {}, is_retry = true) {
        return Ajax.#call('GET', url, params, null, is_retry);
    }
    /**
     * POST 방식으로 데이터를 가져온다.
     * 전송할 데이터는 JSON 방식으로 전송된다.
     *
     * @param {string} url - 요청주소
     * @param {Ajax.Data|FormData} data - 전송할 데이터
     * @param {Ajax.Params} params - GET 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async post(url, data = {}, params = {}, is_retry = true) {
        return Ajax.#call('POST', url, params, data, is_retry);
    }
    /**
     * PATCH 방식으로 데이터를 가져온다.
     * 전송할 데이터는 JSON 방식으로 전송된다.
     *
     * @param {string} url - 요청주소
     * @param {Ajax.Data|FormData} data - 전송할 데이터
     * @param {Ajax.Params} params - GET 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async patch(url, data = {}, params = {}, is_retry = true) {
        return Ajax.#call('PATCH', url, params, data, is_retry);
    }
    /**
     * DELETE 방식으로 데이터를 가져온다.
     * 전송할 데이터는 JSON 방식으로 전송된다.
     *
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async delete(url, params = {}, is_retry = true) {
        return Ajax.#call('DELETE', url, params, null, is_retry);
    }
    /**
     * SYNC 방식으로 데이터를 가져온다.
     * 전송할 데이터는 JSON 방식으로 전송된다.
     *
     * @param {string} url - 요청주소
     * @param {Ajax.Params} params - GET 데이터
     * @param {boolean|number} is_retry - 재시도여부
     * @return {Promise<Ajax.Results>} results - 요청결과
     */
    static async sync(url, params = {}, is_retry = true) {
        return Ajax.#call('SYNC', url, params, null, is_retry);
    }
    static setErrorHandler(handler) {
        Ajax.errorHandler = handler;
    }
}
(function (Ajax) {
    class Progress {
        bytesTotal;
        bytesCurrent;
        total;
        current;
        latests;
        chunks;
        controller;
        signal;
        aborted;
        static init() {
            return new Ajax.Progress();
        }
        /**
         * 프로그래스바 클래스를 정의한다.
         */
        constructor() {
            this.controller = new AbortController();
            this.signal = this.controller.signal;
            this.aborted = false;
        }
        /**
         * 프로그래스바 빈 결과객체를 가져온다.
         *
         * @param {Object} results - 일부 결과 데이터
         * @return {Ajax.Progress.Results} - 전체 결과 데이터
         */
        getResults(results = null) {
            return {
                success: results?.success ?? false,
                message: results?.message ?? null,
                current: results?.current ?? 0,
                total: results?.total ?? 0,
                data: results?.data ?? null,
                percentage: results?.percentage ?? 0,
                end: results?.end ?? false,
                aborted: this.aborted,
            };
        }
        /**
         * 멀티바이트 문자열의 정확한 크기(Bytes) 계산한다.
         *
         * @param {string} text - 계산할 문자열
         * @return {number} bytes - 문자열 크기(Bytes)
         */
        getByteLength(text) {
            if (text != undefined && text != '') {
                let bytes = 0;
                let char;
                for (let i = 0; (char = text.charCodeAt(i++)); bytes += char >> 11 ? 3 : char >> 7 ? 2 : 1)
                    ;
                return bytes;
            }
            else {
                return 0;
            }
        }
        /**
         * 프로그래스바를 위한 데이터를 가져온다.
         *
         * @return {Ajax.Progress.Results} progress
         */
        getProgressData() {
            let chunksAll = new Uint8Array(this.bytesCurrent);
            let position = 0;
            for (const chunk of this.chunks) {
                chunksAll.set(chunk, position);
                position += chunk.length;
            }
            let response = new TextDecoder('utf-8').decode(chunksAll);
            const lines = response.split('\n');
            let latest = null;
            while (lines.length > 0) {
                let line = lines.pop();
                try {
                    latest = JSON.parse(line.trim());
                    if (typeof latest == 'object')
                        break;
                }
                catch (e) { }
            }
            if (latest == null) {
                return this.getResults();
            }
            return this.getResults({
                ...latest,
                success: true,
                percentage: Math.max(100, (this.bytesCurrent / this.bytesTotal - 10000) * 100),
            });
        }
        /**
         * 실제 프로그래스바 요청을 처리한다.
         *
         * @param {method} method - 요청방식
         * @param {string} url - 요청주소
         * @param {Ajax.Params} params - GET 데이터
         * @param {Ajax.Data|FormData} data - 전송할 데이터
         * @param {Function} callback - 프로그래스 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async #fetch(method = 'GET', url, params = {}, data = {}, callback) {
            const requestUrl = new URL(url, location.origin);
            for (const name in params) {
                if (params[name] === null) {
                    requestUrl.searchParams.delete(name);
                }
                else {
                    requestUrl.searchParams.append(name, params[name].toString());
                }
            }
            url = requestUrl.toString();
            const headers = {
                'X-Method': method,
                'Accept-Language': iModules.getLanguage(),
                'Accept': 'application/json',
            };
            if (method == 'SYNC') {
                method = 'GET';
            }
            if (method == 'EXCEL') {
                method = 'POST';
            }
            let body = null;
            if (method == 'POST' || method == 'PUT') {
                if (data instanceof FormData) {
                    body = data;
                }
                else {
                    headers['Content-Type'] = 'application/json; charset=utf-8';
                    body = JSON.stringify(data);
                }
            }
            try {
                const response = (await fetch(url, {
                    signal: this.signal,
                    method: method,
                    headers: headers,
                    body: body,
                    cache: 'no-store',
                    redirect: 'follow',
                }).catch(async (e) => {
                    throw new Error(e);
                }));
                const reader = response.body.getReader();
                this.chunks = [];
                this.bytesCurrent = 0;
                this.bytesTotal = parseInt(response.headers.get('Content-Length') ?? '2010000', 10);
                this.total = parseInt(response.headers.get('X-Progress-Total') ?? '-1', 10);
                if (this.bytesTotal >= 0 && this.total >= 0) {
                    callback(this.getResults({ success: true, current: 0, total: this.total }));
                }
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) {
                        const success = this.isSuccess();
                        if (success !== true) {
                            const results = this.getResults({
                                success: false,
                                message: typeof success == 'boolean' ? null : success?.message,
                                end: true,
                            });
                            callback(results);
                            return results;
                        }
                        const data = this.getProgressData();
                        callback(data);
                        return data;
                    }
                    this.chunks.push(value);
                    this.bytesCurrent += value.length;
                    if (this.bytesTotal >= 0 && this.total >= 0) {
                        callback(this.getProgressData());
                    }
                }
            }
            catch (e) {
                const results = this.getResults({ end: true });
                callback(results);
                return results;
            }
        }
        /**
         * 프로그래스바 요청을 취소한다.
         */
        abort() {
            this.aborted = true;
            this.controller.abort();
        }
        /**
         * GET 요청을 프로그래스바 요청과 함께 가져온다.
         *
         * @param {string} url - 요청주소
         * @param {Ajax.Params} params - GET 데이터
         * @param {Function} callback - 프로그래스 데이터를 받을 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async get(url, params = {}, callback) {
            return await this.#fetch('GET', url, params, null, callback);
        }
        /**
         * POST 요청을 프로그래스바 요청과 함께 가져온다.
         *
         * @param {string} url - 요청주소
         * @param {Ajax.Data|FormData} data - 전송할 데이터
         * @param {Ajax.Params} params - GET 데이터
         * @param {Function} callback - 프로그래스 데이터를 받을 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async post(url, data = {}, params = {}, callback) {
            return await this.#fetch('POST', url, params, data, callback);
        }
        /**
         * DELETE 요청을 프로그래스바 요청과 함께 가져온다.
         *
         * @param {string} url - 요청주소
         * @param {Ajax.Params} params - GET 데이터
         * @param {Function} callback - 프로그래스 데이터를 받을 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async delete(url, params = {}, callback) {
            return await this.#fetch('DELETE', url, params, null, callback);
        }
        /**
         * SYNC 요청을 프로그래스바 요청과 함께 가져온다.
         *
         * @param {string} url - 요청주소
         * @param {Ajax.Params} params - GET 데이터
         * @param {Function} callback - 프로그래스 데이터를 받을 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async sync(url, params = {}, callback) {
            return await this.#fetch('SYNC', url, params, null, callback);
        }
        /**
         * EXCEL 요청을 프로그래스바 요청과 함께 가져온다.
         *
         * @param {string} url - 요청주소
         * @param {Ajax.Data|FormData} data - 전송할 데이터
         * @param {Ajax.Params} params - GET 데이터
         * @param {Function} callback - 프로그래스 데이터를 받을 콜백함수
         * @return {Ajax.Progress.Results} results - 프로그래스 최종완료 결과
         */
        async excel(url, data = {}, params = {}, callback) {
            return await this.#fetch('EXCEL', url, params, data, callback);
        }
        /**
         * 프로그래스바 데이터가 정상적으로 종료되었는지 확인한다.
         *
         * @return {boolean|object} success
         */
        isSuccess() {
            let chunksAll = new Uint8Array(this.bytesCurrent);
            let position = 0;
            for (const chunk of this.chunks) {
                chunksAll.set(chunk, position);
                position += chunk.length;
            }
            let result = new TextDecoder('utf-8').decode(chunksAll);
            if (result.split('\n').pop() == '@') {
                return true;
            }
            else {
                try {
                    return JSON.parse(result.trim());
                }
                catch (e) {
                    return false;
                }
            }
        }
    }
    Ajax.Progress = Progress;
})(Ajax || (Ajax = {}));
