/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * HTML DOM 을 제어한다.
 *
 * @file /scripts/Html.ts
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2022. 12. 1.
 */
class Html {
    static dataValues: WeakMap<object, any> = new WeakMap();

    /**
     * HTML 객체를 생성한다.
     *
     * @param {string} type - 생성할 Node명
     * @param {Object} attributes - 포함할 attribute
     * @param {string=''} text - 포함될 텍스트내용
     * @return {Dom} dom - 생성된 Dom 객체
     */
    static create(type: string, attributes: { [key: string]: string } = {}, text: string = ''): Dom {
        const element = document.createElement(type);
        const dom = new Dom(element);
        for (let key in attributes) {
            dom.setAttr(key, attributes[key]);
        }
        dom.text(text);
        return dom;
    }

    /**
     * HTML 엘리먼트를 Dom 객체로 가져온다.
     *
     * @param {HTMLElement|EventTarget} element - Dom 객체로 생성할 HTML 엘리먼트 객체
     * @return {Dom} dom - 생성된 Dom 객체
     */
    static el(element: HTMLElement | EventTarget): Dom | null {
        if (element instanceof HTMLElement) {
            return new Dom(element as HTMLElement);
        } else {
            return null;
        }
    }

    /**
     * 쿼리셀렉터에 해당하는 DOM Element 를 가져온다.
     *
     * @param {string} selector - 쿼리셀럭터
     * @param {?Dom} context - DOM Element 를 가져올 부모요소
     * @return {?Dom} dom - 쿼리셀럭터에 해당하는 Dom 객체
     */
    static get(selector: string, context?: Dom): Dom | null {
        if (context instanceof Dom === true) {
            return new Dom(context.getEl()?.querySelector(selector) ?? null);
        }

        return new Dom(document.querySelector(selector));
    }

    /**
     * 쿼리셀렉터에 해당하는 모든 DOM Element 를 가져온다.
     *
     * @param {string} selector - 쿼리셀렉터
     * @param {?Dom} context - DOM Element 를 가져올 부모요소
     * @return {Dom[]} elements
     */
    static all(selector: string, context?: Dom): DomList {
        let nodes: NodeList;
        if (context !== undefined && context.constructor.name == 'Dom') {
            nodes = context.getEl()?.querySelectorAll(selector);
        } else {
            nodes = document.querySelectorAll(selector);
        }

        return new DomList(nodes);
    }

    /**
     * HTML 문서의 스크롤 이벤트리스너를 등록한다.
     *
     * @param {EventListener} listener - 이벤트리스너
     */
    static scroll(listener: EventListener): void {
        document.addEventListener('scroll', listener);
    }

    /**
     * HTML 문서의 스크롤위치를 조절한다.
     *
     * @param {number} top - 상단위치
     * @param {boolean} animate - 애니메이션여부
     * @return {number} scrollTop - 스크롤된 위치
     */
    static scrollTop(top?: number, animate: boolean = true): number {
        if (top === undefined) {
            return document.documentElement.scrollTop;
        } else {
            document.documentElement.scroll({ top: top, behavior: animate === true ? 'smooth' : 'auto' });
        }
    }

    /**
     * HTML 문서의 랜더링 완료 이벤트리스너를 등록한다.
     *
     * @param {EventListener} listener - 이벤트리스너
     */
    static ready(listener: EventListener): void {
        document.addEventListener('DOMContentLoaded', listener);
    }
}