<?php
/**
 * 이 파일은 아이모듈의 일부입니다. (https://www.imodules.io)
 *
 * 데이터베이스 인터페이스 추상 클래스를 정의한다.
 *
 * @file /classes/DatabaseInterface.php
 * @author Arzz <arzz@arzz.com>
 * @license MIT License
 * @modified 2022. 2. 16.
 */
abstract class DatabaseInterface {
	/**
	 * 데이터베이스에 접속한다.
	 *
	 * @param object $connector 데이터베이스정보
	 * @return mixed $interface 인터페이스객체
	 */
	public abstract function connect(object $connector):mixed;
	
	/**
	 * 커넥션을 설정한다.
	 *
	 * @param mixed &$connection
	 * @return bool $success
	 */
	public abstract function setConnection(&$connection):bool;
	
	/**
	 * 데이터베이스에 접속이 가능한지 확인한다.
	 *
	 * @param object $connector 데이터베이스정보
	 * @return bool $success 접속성공여부
	 */
	public abstract function checkConnector(object $connector):bool;
	
	/**
	 * 데이터베이스 서버에 ping 을 보낸다.
	 *
	 * @return bool $pong
	 */
	public abstract function ping():bool;
	
	/**
	 * 진행중인 쿼리빌더를 초기화한다.
	 */
	public abstract function reset():void;
	
	/**
	 * 데이터베이스의 전체 테이블목록을 가져온다.
	 *
	 * @param bool $include_desc 테이블구조 포함여부
	 * @return array $tables
	 */
	public abstract function tables(bool $include_desc=false):array;
	
	/**
	 * 테이블명이 존재하는지 확인한다.
	 *
	 * @param string $table 테이블명
	 * @param bool $exists
	 */
	public abstract function exists(string $table):bool;
	
	/**
	 * 테이블의 용량을 가져온다.
	 *
	 * @param string $table 테이블명
	 * @return int $size
	 */
	public abstract function size(string $table):int;
	
	/**
	 * 테이블의 구조를 가져온다.
	 *
	 * @param string $table 테이블명
	 * @return array $desc
	 */
	public abstract function desc(string $table):array;
	
	/**
	 * 테이블의 구조를 비교한다.
	 *
	 * @param string $table 테이블명
	 * @param array $schema 테이블구조
	 * @return bool $is_coincidence
	 */
	public abstract function compare(string $table,array $schema):bool;
	
	/**
	 * 테이블을 생성한다.
	 *
	 * @param string $table 테이블명
	 * @paran object $schema 테이블구조
	 * @return bool $success
	 */
	public abstract function create(string $table,array $schema):bool;
	
	/**
	 * 테이블을 삭제한다.
	 *
	 * @param string $table 테이블명
	 * @return bool $success
	 */
	public abstract function drop(string $table):bool;
	
	/**
	 * 테이블을 비운다.
	 *
	 * @param string $table 테이블명
	 * @return bool $success
	 */
	public abstract function truncate(string $table):bool;
	
	/**
	 * 테이블의 이름을 변경한다.
	 *
	 * @param string $table 변경전 테이블명
	 * @param string $newname 변경할 테이블명
	 * @return bool $success
	 */
	public abstract function rename(string $table,string $newname):bool;
	
	/**
	 * 백업테이블을 생성한다.
	 *
	 * @param string $table 백업할 테이블명
	 * @return bool $success
	 */
	public abstract function backup(string $table):bool;
	
	/**
	 * 컬럼을 추가한다.
	 *
	 * @param string $table 컬럼을 추가할 테이블명
	 * @param object $column 추가할컬럼구조
	 * @param ?string $after 컬럼을 추가할 위치
	 * @return bool $success
	 */
	public abstract function alterAdd(string $table,object $column,?string $after=null):bool;
	
	/**
	 * 컬럼을 수정한다.
	 *
	 * @param string $table 컬럼을 변경할 테이블명
	 * @param string $target 변경할 컬럼명
	 * @param object $column 변경할 컬럼구조
	 * @return bool $success
	 */
	public abstract function alterChange(string $table,string $target,object $column):bool;
	
	/**
	 * 컬럼을 삭제한다.
	 *
	 * @param string $table 컬럼을 삭제할 테이블명
	 * @param string $target 삭제할 컬럼명
	 * @return bool $success
	 */
	public abstract function alterDrop(string $table,string $target):bool;
	
	/**
	 * LOCK 방법을 설정한다.
	 *
	 * @param string $method LOCK METHOD (READ, WRITE)
	 * @return DatabaseInterface $this
	 */
	public abstract function setLockMethod(string $method):DatabaseInterface;
	
	/**
	 * 단일 테이블을 설정된 LOCK 방법에 따라 LOCK 한다.
	 *
	 * @param string $table LOCK할 테이블
	 * @param ?string $method LOCK METHOD (READ, WRITE)
	 * @return bool $success
	 */
	public abstract function lock(string $table,?string $method=null):bool;
	
	/**
	 * 복수 테이블을 설정된 LOCK 방법에 따라 LOCK 한다.
	 *
	 * @param array $tables LOCK할 테이블
	 * @param ?string $method LOCK METHOD (READ, WRITE)
	 * @return bool $success
	 */
	public abstract function locks(array $tables,?string $method=null):bool;
	
	/**
	 * 현재 LOCK 중인 테이블을 UNLOCK 한다.
	 *
	 * @return bool $success
	 */
	public abstract function unlock():bool;
	
	/**
	 * 쿼리빌더 없이 RAW 쿼리를 실행한다.
	 *
	 * @param string $query 쿼리문
	 * @param array $bindParams 바인딩할 변수
	 * @return DatabaseInterface $this
	 */
	public abstract function query(string $query,?array $bindParams=null):DatabaseInterface;
	
	/**
	 * SELECT 쿼리빌더를 시작한다.
	 *
	 * @param array $columns 가져올 컬럼명
	 * @return DatabaseInterface $this
	 */
	public abstract function select(array $columns=[]):DatabaseInterface;
	
	/**
	 * INSERT 쿼리빌더를 시작한다.
	 *
	 * @param string $table 테이블명
	 * @param array $data 저장할 데이터 ([컬럼명=>값])
	 * @return DatabaseInterface $this
	 */
	public abstract function insert(string $table,array $data):DatabaseInterface;
	
	/**
	 * REPLACE 쿼리빌더를 시작한다.
	 *
	 * @param string $table 테이블명
	 * @param array $data 저장할 데이터 ([컬럼명=>값])
	 * @return DatabaseInterface $this
	 */
	public abstract function replace(string $table,array $data):DatabaseInterface;
	
	/**
	 * UPDATE 쿼리빌더를 시작한다.
	 *
	 * @param string $table 테이블명
	 * @param array $data 변경할 데이터 ([컬럼명=>값])
	 * @return DatabaseInterface $this
	 */
	public abstract function update(string $table,array $data):DatabaseInterface;
	
	/**
	 * DELETE 쿼리빌더를 시작한다.
	 *
	 * @param string $table 테이블명
	 * @return DatabaseInterface $this
	 */
	public abstract function delete(string $table):DatabaseInterface;
	
	/**
	 * FROM 절을 정의한다.
	 *
	 * @param string $table 테이블명
	 * @param ?string $alias 테이블별칭
	 */
	public abstract function from(string $table,?string $alias=null):DatabaseInterface;
	
	/**
	 * WHERE 절을 정의한다. (AND조건)
	 *
	 * @param string $whereProp WHERE 조건절 (컬럼명 또는 WHERE 조건문)
	 * @param mixed $whereValue 검색할 조건값 (컬럼데이터 또는 WHERE 조건문에 바인딩할 값의 배열)
	 * @param ?string $operator 조건 (=, IN, NOT IN, LIKE 등)
	 * @return DatabaseInterface $this
	 */
	public abstract function where(string $whereProp,$whereValue=null,?string $operator=null):DatabaseInterface;
	
	/**
	 * WHERE 절을 정의한다. (OR조건)
	 *
	 * @param string $whereProp WHERE 조건절 (컬럼명 또는 WHERE 조건문)
	 * @param mixed $whereValue 검색할 조건값 (컬럼데이터 또는 WHERE 조건문에 바인딩할 값의 배열)
	 * @param ?string $operator 조건 (=, IN, NOT IN, LIKE 등)
	 * @return DatabaseInterface $this
	 */
	public abstract function orWhere(string $whereProp,$whereValue=null,?string $operator=null):DatabaseInterface;
	
	/**
	 * HAVING 절을 정의한다. (AND조건)
	 *
	 * @param string $havingProp HAVING 조건절 (컬럼명 또는 WHERE 조건문)
	 * @param mixed $havingValue 검색할 조건값 (컬럼데이터 또는 WHERE 조건문에 바인딩할 값의 배열)
	 * @param ?string $operator 조건 (=, IN, NOT IN, LIKE 등)
	 * @return DatabaseInterface $this
	 */
	public abstract function having($havingProp,$havingValue=null,?string $operator=null):DatabaseInterface;
	
	/**
	 * HAVING 절을 정의한다. (OR조건)
	 *
	 * @param string $havingProp HAVING 조건절 (컬럼명 또는 WHERE 조건문)
	 * @param mixed $havingValue 검색할 조건값 (컬럼데이터 또는 WHERE 조건문에 바인딩할 값의 배열)
	 * @param ?string $operator 조건 (=, IN, NOT IN, LIKE 등)
	 * @return DatabaseInterface $this
	 */
	public abstract function orHaving(string $havingProp,$havingValue=null,?string $operator=null):DatabaseInterface;
	
	/**
	 * JOIN 절을 정의한다. (AND조건)
	 *
	 * @param string $joinTable JOIN 할 prefix 가 포함되지 않은 테이블명
	 * @param string $joinCondition JOIN 조건
	 * @param string $joinType 조인형태 (LEFT, RIGHT, OUTER, INNER, LEFT OUTER, RIGHT OUTER)
	 * @return DatabaseInterface $this
	 */
	public abstract function join(string $joinTable,string $joinCondition,string $joinType=''):DatabaseInterface;
	
	/**
	 * ORDER 절을 정의한다.
	 *
	 * @param string $orderByField 정렬할 필드명
	 * @param string $orderbyDirection 정렬순서 (ASC, DESC)
	 * @param ?array $customFields 커스덤필드배열 (테이블에 정의된 컬럼이 아닌 경우)
	 * @return DatabaseInterface $this
	 */
	public abstract function orderBy(string $orderByField,string $orderbyDirection='DESC',?array $customFields=null):DatabaseInterface;
	
	/**
	 * GROUP 절을 정의한다.
	 *
	 * @param string $groupByField GROUP 할 컬럼명
	 * @return DatabaseInterface $this
	 */
	public abstract function groupBy(string $groupByField):DatabaseInterface;
	
	/**
	 * LIMIT 절을 정의한다.
	 *
	 * @param int $start 시작점
	 * @param ?int $limit 가져올 갯수 ($limit 이 정의되지 않은 경우, 0번째 부터 $start 갯수만큼 가져온다.)
	 * @return DatabaseInterface $this
	 */
	public abstract function limit(int $start,?int $limit=null):DatabaseInterface;
	
	/**
	 * 쿼리를 실행한다.
	 *
	 * @return object $results 실행결과
	 */
	public abstract function execute():object;
	
	/**
	 * SELECT 쿼리문에 의해 선택된 데이터의 갯수를 가져온다.
	 *
	 * @return int $count
	 */
	public abstract function count():int;
	
	/**
	 * SELECT 쿼리문에 의해 선택된 데이터가 존재하는지 확인한다.
	 *
	 * @return boolean $has
	 */
	public abstract function has():bool;
	
	/**
	 * SELECT 쿼리문에 의해 선택된 데이터를 가져온다.
	 *
	 * @param ?string $field 필드명 (필드명을 지정할 경우, 컬럼명->컬럼값이 아닌 해당 필드명의 값만 배열로 반환한다.)
	 * @return array $items
	 */
	public abstract function get(?string $field=null):array;
	
	/**
	 * SELECT 쿼리문에 의해 선택된 데이터중 한개만 가져온다.
	 *
	 * @param ?string $field 필드명 (필드명을 지정할 경우, 컬럼명->컬럼값이 아닌 해당 필드명의 값만 반환한다.)
	 * @return mixed $item
	 */
	public abstract function getOne(?string $field=null):mixed;
	
	/**
	 * 현재까지 쿼리빌더에 의해 생성된 쿼리를 복제한다.
	 *
	 * @return DatabaseInterface $copy 복제된 쿼리빌더 클래스
	 */
	public abstract function copy():DatabaseInterface;
	
	/**
	 * 마지막에 실행된 쿼리문을 가져온다.
	 *
	 * @return string $query
	 */
	public abstract function getLastQuery():?string;
}
?>