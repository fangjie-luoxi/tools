package response

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type Resp struct {
	RespTp      string // 返回结构体类型
	ErrShowType int    // 错误展示类型
}

// NewResp 创建返回结构体
// respTp: antd 阿里antd的统一返回格式、bee beego的返回风格
// showType: 0 silent; 1 message.warn; 2 message.error; 4 notification; 9 page
func NewResp(respTp string, showType int) *Resp {
	return &Resp{RespTp: respTp, ErrShowType: showType}
}

// Error 失败数据处理
func (r *Resp) Error(c *gin.Context, code int, err error, msg string) {
	res := antdResponse{
		Success:   false,
		ErrorCode: strconv.Itoa(code),
		ShowType:  r.ErrShowType,
		TraceId:   "",
		Host:      "",
	}
	if err != nil {
		res.ErrorMessage = err.Error()
	}
	if msg != "" {
		res.ErrorMessage = msg
	}
	c.JSON(code, res)
}

// OK 通常成功数据处理
func (r *Resp) OK(c *gin.Context, code int, data interface{}) {
	respTp := r.getRespType(c)
	switch respTp {
	case "bee":
		c.JSON(code, data)
		return
	default:
		c.JSON(code, antdResponse{
			Success: true,
			Data:    data,
			TraceId: "",
			Host:    "",
		})
	}
}

// PageOK 分页数据处理
func (r *Resp) PageOK(c *gin.Context, data interface{}, count int64, offset int, limit int) {
	respTp := r.getRespType(c)
	switch respTp {
	case "bee":
		var beeRes lgPager
		beeRes.Page = beeRes.pageUtil(count, int64(offset/limit+1), int64(limit))
		beeRes.List = data
		c.JSON(200, beeRes)
	default:
		c.JSON(http.StatusOK, antdResponse{
			Success:  true,
			Data:     data,
			Total:    count,
			Current:  offset/limit + 1,
			PageSize: limit,
			ShowType: 2,
			TraceId:  "",
			Host:     "",
		})
	}
}

// antdResponse antd的标准响应
type antdResponse struct {
	// 基本数据
	Success  bool        `json:"success"`
	Data     interface{} `json:"data"`
	Total    int64       `json:"total"`
	Current  int         `json:"current"`
	PageSize int         `json:"pageSize"`
	// 附带信息
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	ShowType     int    `json:"showType"`
	TraceId      string `json:"traceId"`
	Host         string `json:"host"`
}

type lgPage struct {
	PageNo     int64
	PageSize   int64
	TotalPage  int64
	TotalCount int64
	FirstPage  bool
	LastPage   bool
}

type lgPager struct {
	Page lgPage
	List interface{}
}

func (p *lgPager) pageUtil(count int64, pageNo int64, pageSize int64) lgPage {
	tp := count / pageSize
	if count%pageSize > 0 {
		tp = count/pageSize + 1
	}
	lastPage := pageNo == tp
	if tp == 0 {
		lastPage = true
	}
	return lgPage{PageNo: pageNo, PageSize: pageSize, TotalPage: tp, TotalCount: count, FirstPage: pageNo == 1, LastPage: lastPage}
}

// 获取返回的数据结构
func (r *Resp) getRespType(c *gin.Context) string {
	respTp := r.RespTp
	if respTp == "" {
		respTp = "antd"
	}
	tp := c.Query("resp_type")
	if tp != "" {
		respTp = tp
	}
	tp = c.Query("resp")
	if tp != "" {
		respTp = tp
	}
	return respTp
}

// Error 错误处理
func Error(c *gin.Context, code int, msg string) {
	res := antdResponse{
		Success:      false,
		ErrorCode:    strconv.Itoa(code),
		ShowType:     4,
		TraceId:      "",
		Host:         c.ClientIP(),
		ErrorMessage: msg,
	}
	c.JSON(code, res)
}

// Success 成功返回
func Success(c *gin.Context, code int, data interface{}) {
	c.JSON(code, antdResponse{
		Success: true,
		Data:    data,
		TraceId: "",
		Host:    c.ClientIP(),
	})
}
