package query

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Param 请求参数
type Param struct {
	Table   string `form:"table"`    // 要查询的表
	Query   string `form:"query"`    // 条件查询 格式: 字段1:值1,字段2:值2 eg: Id:1,Post.Id:2
	Or      string `form:"or"`       // 或查询 格式: 字段1:值1,字段2:值2 eg: Id:1,Post.Id:2
	NOT     string `form:"not"`      // not条件查询 格式: 字段1:值1,字段2:值2 eg: Id:1,Post.Id:2
	Select  string `form:"select"`   // 选择的字段 格式: 字段1,字段2
	Fields  string `form:"fields"`   // 返回的字段 格式: 字段1,字段2
	Sortby  string `form:"sortby"`   // 排序的字段 格式: 字段1,字段2
	Order   string `form:"order"`    // 排序的方式 enum:desc:降序,asc:升序
	OrderBy string `form:"order_by"` // 排序 格式: 字段1 desc,字段2 asc
	Load    string `form:"load"`     // 加载关联  格式: 关联字段1,关联字段2 eg: User,Posts

	Limit     int `form:"limit,default=10"` // 返回的数据量
	Page      int `form:"page,default=1"`   // 是否返回分页数据
	Offset    int `form:"offset,default=0"` // 偏移量
	GetCounts int `form:"getcounts"`        // 只返回数量
}

// Query 查询条件
type Query struct {
	Table      string   // 要查询的表
	Select     []string // 选择字段
	SelectResp []string // 选择返回的字段
	Where      []Where  // 过滤
	Joins      []string // join查询
	Or         []Where  // Or 或查询
	NOT        []Where  // NOT 条件
	Load       []Load   // load 加载
	Order      string   // Order 排序
	Limit      int      // 限制
	Offset     int      // 偏移
	Group      string   // 分组
	Having     string   // 过滤
	Distinct   string   // 选择不同
	Count      string   // 返回Count, T:返回count和数据,F:返回数据不返回count,count:只返回count
}

// Where Where查询
type Where struct {
	Exp   string      // 表达式
	Value interface{} // 值
}

// Load 预加载
type Load struct {
	Table string
	Where []Where // 条件过滤
	Order string  // Order 排序
	Limit int     // 限制返回数量
}

// M2MQuery 多对多查询
type M2MQuery interface {
	GetM2MJoin(string) string // 获取多对多关系
	TableName() string        // 获取表名
}

// NewQuery 通过gin.Context创建查询
func NewQuery(c *gin.Context, model M2MQuery) (*Query, error) {
	var param Param
	err := c.ShouldBindQuery(&param)
	if err != nil {
		return nil, err
	}
	return NewQueryByParam(&param, model)
}

// NewQueryByParam 通过Param创建查询
func NewQueryByParam(param *Param, model M2MQuery) (*Query, error) {
	tb := model.TableName()
	param.Table = tb

	var query Query
	query.Table = tb
	if param.Query != "" {
		query.Where = paramToWhere(param.Query, tb)
		query.Joins = param.paramToJoin(model)
	}
	if param.Or != "" {
		query.Or = paramToWhere(param.Or, tb)
	}
	if param.NOT != "" {
		query.NOT = paramToWhere(param.NOT, tb)
	}
	if param.Load != "" {
		query.Load = param.paramToLoad()
	}
	if param.Sortby != "" {
		query.Order = param.paramToOrder()
	}
	if param.OrderBy != "" {
		newOrder := param.paramToOrderBy()
		if query.Order != "" {
			newOrder = query.Order + "," + param.paramToOrderBy()
		}
		query.Order = newOrder
	}
	query.Limit = param.Limit
	if param.Limit == 0 {
		query.Limit = 10
	}
	query.Offset = param.Offset
	if param.GetCounts == 1 {
		query.Count = "count"
	}
	if param.Page == -1 {
		query.Count = "F"
	}
	if param.Fields != "" {
		query.Select = param.paramToSelect()
	}
	if param.Select != "" {
		query.SelectResp = strings.Split(param.Select, ",")
	}
	return &query, nil
}

// DBQuery 封装查询的db
func (q *Query) DBQuery() func(tx *gorm.DB) *gorm.DB {
	return func(tx *gorm.DB) *gorm.DB {
		for _, filter := range q.Where {
			tx.Where(filter.Exp, filter.Value)
		}
		for _, join := range q.Joins {
			tx.Joins(join)
		}
		for _, or := range q.Or {
			tx.Or(or.Exp, or.Value)
		}
		for _, not := range q.NOT {
			tx.Not(not.Exp, not.Value)
		}
		if q.Count == "count" {
			return tx
		}
		if q.Order != "" {
			tx.Order(q.Order)
		}
		for _, load := range q.Load {
			order := load.Order
			filter := load.Where
			limit := load.Limit
			tx.Preload(load.Table, func(db *gorm.DB) *gorm.DB {
				for _, f := range filter {
					db = db.Where(f.Exp, f.Value)
				}
				if order != "" {
					db = db.Order(order)
				}
				if limit != 0 {
					db = db.Limit(limit)
				}
				return db
			})
		}
		return tx
	}
}

// DBSelect 字段过滤的db
func (q *Query) DBSelect() func(tx *gorm.DB) *gorm.DB {
	var selectList []string
	if len(q.Joins) > 0 && len(q.Select) == 0 {
		selectList = append(selectList, q.Table+".*")
	}
	if len(q.Select) > 0 {
		selectList = append(selectList, q.Select...)
	}
	return func(tx *gorm.DB) *gorm.DB {
		if len(selectList) > 0 {
			tx.Select(strings.Join(selectList, ","))
		}
		return tx
	}
}

// GetSelectMap 获取指定字段的map
func (q *Query) GetSelectMap(dataList interface{}, fields string) interface{} {
	selectList := strings.Split(fields, ",")
	if len(q.SelectResp) != 0 {
		selectList = append(selectList, q.SelectResp...)
	}
	if len(selectList) <= 0 {
		return dataList
	}
	var resMap []map[string]interface{}
	v1 := reflect.ValueOf(dataList)
	if v1.Kind() != reflect.Slice {
		return dataList
	}
	for i := 0; i < v1.Len(); i++ {
		ele := v1.Index(i).Interface()
		v2 := reflect.ValueOf(ele)
		if v2.Kind() == reflect.Ptr {
			v2 = v2.Elem()
		}

		if v2.Kind() != reflect.Struct { // 非结构体返回错误提示
			return dataList
		}
		t := v2.Type()
		out := make(map[string]interface{})
		// 返回指定字段
		for _, field := range selectList {
			fi, isIn := t.FieldByName(field)
			if isIn {
				out[fi.Name] = v2.FieldByName(field).Interface()
			}
		}
		resMap = append(resMap, out)
	}
	return resMap
}

func (p *Param) paramToLoad() []Load {
	param := p.Load
	var loadList []Load
	for _, cond := range strings.Split(param, ",") {
		if cond == "" {
			continue
		}
		kv := strings.Split(cond, "|")
		if len(kv) == 1 {
			loadList = append(loadList, Load{
				Table: kv[0],
				Where: nil,
				Limit: 0,
			})
		} else {
			table := kv[0]
			var filter []Where
			var order []string
			limit := 0
			for _, condition := range kv[1:] {
				conditionKV := strings.Split(condition, ":")
				if strings.Contains(conditionKV[0], "order") {
					if strings.Contains(conditionKV[0], "desc") {
						order = append(order, camelCase(conditionKV[1])+" DESC")
					} else {
						order = append(order, camelCase(conditionKV[1]))
					}
				} else if conditionKV[0] == "limit" {
					limitNum, err := strconv.Atoi(conditionKV[1])
					if err == nil {
						limit = limitNum
					}
				} else {
					where := paramToWhere(condition, "")
					filter = append(filter, where...)
				}
			}
			orderStr := strings.Join(order, ",")
			loadList = append(loadList, Load{
				Table: table,
				Where: filter,
				Order: orderStr,
				Limit: limit,
			})
		}
	}
	return loadList
}

func (p *Param) paramToOrder() string {
	tb := p.Table
	var sortBy []string
	var orderBy []string
	for _, item := range strings.Split(p.Sortby, ",") {
		sortBy = append(sortBy, camelCase(item))
	}
	for _, item := range strings.Split(p.Order, ",") {
		orderBy = append(orderBy, camelCase(item))
	}
	if len(sortBy) == 0 {
		return ""
	}
	if len(sortBy) != len(orderBy) {
		if len(orderBy) == 1 {
			var orderStr []string
			for _, sortStr := range sortBy {
				if !strings.Contains(sortStr, ".") {
					sortStr = tb + "." + sortStr
				}
				orderStr = append(orderStr, sortStr+" "+p.Order)
			}
			return strings.Join(orderStr, ",")
		}
		if len(orderBy) == 0 {
			var orderStr []string
			for _, sortStr := range sortBy {
				if !strings.Contains(sortStr, ".") {
					sortStr = tb + "." + sortStr
				}
				orderStr = append(orderStr, sortStr)
			}
			return strings.Join(orderStr, ",")
		}
		return ""
	} else {
		var orderStr []string
		for i := 0; i < len(sortBy); i++ {
			if len(orderBy) < i || orderBy == nil {
				break
			}
			if !strings.Contains(sortBy[i], ".") {
				sortBy[i] = tb + "." + sortBy[i]
			}
			orderStr = append(orderStr, sortBy[i]+" "+orderBy[i])
		}
		return strings.Join(orderStr, ",")
	}
}

func (p *Param) paramToJoin(m M2MQuery) []string {
	joinMap := make(map[string][]joinWhere)
	for _, cond := range strings.Split(p.Query, ",") {
		if cond == "" {
			continue
		}
		kv := strings.SplitN(cond, ":", 2)
		if len(kv) != 2 || kv[1] == "" {
			continue
		}
		if strings.Contains(kv[0], ".") {
			tbList := strings.Split(kv[0], ".")
			joinMap[strings.Join(tbList[:len(tbList)-1], ".")] = append(joinMap[strings.Join(tbList[:len(tbList)-1], ".")], joinWhere{
				Exp:   tbList[len(tbList)-1],
				Value: kv[1],
			})
			continue
		}
	}
	return p.joinToList(m, joinMap)
}

func (p *Param) paramToOrderBy() string {
	tb := p.Table
	var sortBy []string
	for _, item := range strings.Split(p.OrderBy, ",") {
		sortBy = append(sortBy, camelCase(item))
	}

	if len(sortBy) == 0 {
		return ""
	}
	var orderStr []string
	for _, sortStr := range sortBy {
		if !strings.Contains(sortStr, ".") {
			sortStr = tb + "." + sortStr
		}
		orderStr = append(orderStr, sortStr)
	}
	return strings.Join(orderStr, ",")
}

func (p *Param) paramToSelect() []string {
	tb := p.Table
	var selectList []string
	for _, item := range strings.Split(p.Fields, ",") {
		if !strings.Contains(item, ".") {
			item = tb + "." + item
		}
		selectList = append(selectList, camelCase(item))
	}

	return selectList
}

func (p *Param) joinToList(m M2MQuery, joinMap map[string][]joinWhere) []string {
	// inner join 表2 on 表1.公共字段=表2.公共字段 inner join 表3 on 表2.公共字段=表3.公共字段
	var joinStrList []string

	for jStr, terms := range joinMap {
		joinList := strings.Split(jStr, ".")
		joinStr := ""
		joinTb := p.Table
		for i := 0; i < len(joinList); i++ {
			m2mJoin := m.GetM2MJoin(joinList[i])
			if m2mJoin != "" {
				joinStr = m2mJoin
				joinTb = camelCase(joinList[i])
				break
			}
			join := camelCase(joinList[i])
			joinStr += fmt.Sprintf("JOIN %s ON %s.id = %s.%s_id ", join, join, joinTb, join)
			joinTb = join
		}
		var termList []string
		for _, term := range terms {
			fieldStr := camelCase(term.Exp)
			factor := "= ?"
			valueStr := term.Value
			if strings.Contains(fieldStr, "__") {
				fieldList := strings.Split(fieldStr, "__")
				if len(fieldList) == 2 {
					opt, ok := mysqlOperators[fieldList[1]]
					if ok {
						fieldStr = camelCase(fieldList[0])
						factor = opt
						exp, ok := expValue[fieldList[1]]
						if ok {
							valueStr = strings.ReplaceAll(exp, "?", term.Value)
						}
					}
				}
			}
			if strings.Contains(valueStr, "|") {
				valueStr = "('" + strings.Join(strings.Split(valueStr, "|"), "','") + "')"
			} else {
				valueStr = "'" + valueStr + "'"
			}
			factor = strings.ReplaceAll(factor, "?", valueStr)
			termList = append(termList, fmt.Sprintf("%s.%s %s", joinTb, fieldStr, factor))
		}
		queryStr := fmt.Sprintf("%s AND %s", joinStr, strings.Join(termList, " AND "))
		joinStrList = append(joinStrList, queryStr)
	}
	return joinStrList
}

func paramToWhere(param string, tb string) []Where {
	var filters []Where
	for _, cond := range strings.Split(param, ",") {
		kv := strings.SplitN(cond, ":", 2)
		if len(kv) != 2 || kv[1] == "" || strings.Contains(kv[0], ".") {
			continue
		}
		if kv[0] == "search" {
			filters = append(filters, searchToWhere(kv[1])...)
			continue
		}
		if kv[0] == "dsearch" {
			filters = append(filters, dSearchToWhere(kv[1])...)
			continue
		}
		field := tb + "." + camelCase(kv[0])
		if tb == "" {
			field = camelCase(kv[0])
		}
		factor := " = ?"
		value := kv[1]
		if strings.Contains(kv[0], "__") {
			fieldList := strings.Split(kv[0], "__")
			if len(fieldList) != 2 {
				continue
			}
			opt, ok := mysqlOperators[fieldList[1]]
			if ok {
				field = camelCase(fieldList[0])
				factor = opt
				exp, ok := expValue[fieldList[1]]
				if ok {
					value = strings.ReplaceAll(exp, "?", value)
				}
			}
		}
		filter := Where{
			Exp:   field + " " + factor,
			Value: value,
		}
		vList := strings.Split(value, "|")
		if len(vList) > 1 {
			filter.Value = vList
		}
		filters = append(filters, filter)
	}
	return filters
}

type joinWhere struct {
	Exp   string
	Value string
}

// searchToWhere 为了兼容beego
func searchToWhere(search string) []Where {
	var filters []Where
	searchArr := strings.Split(search, "^")
	searchMap := make(map[string]map[string]interface{}, len(searchArr))
	if len(searchArr) > 0 {
		for _, v := range searchArr {
			searchFields := strings.Split(v, "|")
			var keyStr []string
			valueStr := make(map[string]interface{})
			i := 1
			for _, item := range searchFields {
				filed := strings.Split(item, ">")
				if len(filed) == 2 {
					value := "value" + strconv.Itoa(i)
					keyStr = append(keyStr, camelCase(filed[0])+" LIKE @"+value)
					valueStr[value] = "%" + filed[1] + "%"
					i += 1
				}
			}
			searchMap["("+strings.Join(keyStr, " OR ")+")"] = valueStr
		}
	}
	for k, v := range searchMap {
		filters = append(filters, Where{
			Exp:   k,
			Value: v,
		})
	}
	return filters
}

// dSearchToWhere 为了兼容beego
func dSearchToWhere(search string) []Where {
	var filters []Where
	searchArr := strings.Split(search, "^")
	searchMap := make(map[string]map[string]interface{}, len(searchArr))
	if len(searchArr) > 0 {
		for _, v := range searchArr {
			searchFields := strings.Split(v, "|")
			var keyStr []string
			valueStr := make(map[string]interface{})
			i := 1
			for _, item := range searchFields {
				filed := strings.Split(item, ">")
				if len(filed) == 2 {
					value := "value" + strconv.Itoa(i)
					keyStr = append(keyStr, camelCase(filed[0])+" = @"+value)
					valueStr[value] = filed[1]
					i += 1
				}
			}
			searchMap["("+strings.Join(keyStr, " OR ")+")"] = valueStr
		}
	}
	for k, v := range searchMap {
		filters = append(filters, Where{
			Exp:   k,
			Value: v,
		})
	}
	return filters
}

var mysqlOperators = map[string]string{
	"like":        "LIKE ?",
	"exact":       "= ?",
	"iexact":      "LIKE ?",
	"strictexact": "= BINARY ?",
	"contains":    "LIKE BINARY ?",
	"icontains":   "LIKE ?",
	// "regex":       "REGEXP BINARY ?",
	// "iregex":      "REGEXP ?",
	"gt":          "> ?",
	"gte":         ">= ?",
	"lt":          "< ?",
	"lte":         "<= ?",
	"eq":          "= ?",
	"ne":          "!= ?",
	"startswith":  "LIKE BINARY ?",
	"endswith":    "LIKE BINARY ?",
	"istartswith": "LIKE ?",
	"iendswith":   "LIKE ?",
	"in":          "IN (?)",
}

var expValue = map[string]string{
	"like":        "%?%",
	"exact":       "%?%",
	"iexact":      "%?%",
	"contains":    "%?%",
	"icontains":   "%?%",
	"startswith":  "?%",
	"endswith":    "%?",
	"istartswith": "?%",
	"iendswith":   "%?",
}

// camelCase 驼峰小写，遇到.时不加_
func camelCase(name string) string {
	newstr := make([]byte, 0, len(name)+1)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isUpper := 'A' <= c && c <= 'Z'; isUpper {
			if i > 0 && name[i-1] != '.' {
				newstr = append(newstr, '_')
			}
			c += 'a' - 'A'
		}
		newstr = append(newstr, c)
	}

	return *(*string)(unsafe.Pointer(&newstr))
}
