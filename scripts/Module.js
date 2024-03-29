/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 아이모듈의 각 모듈의 자바스크립트 클래스의 부모클래스를 정의한다.
 *
 * @file /scripts/Module.ts
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2024. 1. 26.
 */
class Module extends Component {
    /**
     * 모듈 클래스를 생성한다.
     *
     * @param {string} name - 모듈명
     */
    constructor(name) {
        super();
        this.name = name;
        this.type = 'module';
    }
    /**
     * 해당 모듈의 Dom 객체를 초기화한다.
     *
     * @param {Dom} $dom - 현재 모듈의 DOM 객체
     */
    init($dom) { }
}
