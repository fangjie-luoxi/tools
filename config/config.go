// Package config
// 系统配置
// 默认获取配置路径`conf/app.yaml`,可以直接传配置文件的内容
package config

import (
	"bytes"

	"github.com/spf13/viper"
)

type Config struct {
	Vp *viper.Viper // 配置
}

// SetUp 初始化
// 读取配置顺序:
// 1: 当param的参数个数为2时 第一个参数为文件配置路径、第二个参数为配置文件名称(没有后缀)
// 2: 当param的参数个数不为2时 默认读取 conf/ 下的app
// 当读取配置文件失败，并且param参数个数为1时，直接加载参数的字符进行配置
func SetUp(param ...string) *Config {
	var cfg Config
	vp := viper.New()
	cfg.Vp = vp
	vp.SetConfigType("yaml")
	if len(param) == 2 {
		vp.AddConfigPath(param[0])
		vp.SetConfigName(param[1])
	} else {
		vp.SetConfigName("app")
		vp.AddConfigPath("conf/")
	}
	err := vp.ReadInConfig()
	if err == nil {
		return &cfg
	}
	if len(param) == 1 {
		_ = vp.ReadConfig(bytes.NewBuffer([]byte(param[0])))
	}
	return &cfg
}

func (c *Config) String(s string) string {
	return c.Vp.GetString(s)
}

func (c *Config) DefaultString(s string, def string) string {
	if c.Vp.IsSet(s) {
		return c.Vp.GetString(s)
	}
	return def
}

func (c *Config) Bool(s string) bool {
	return c.Vp.GetBool(s)
}

func (c *Config) DefaultBool(s string, def bool) bool {
	if c.Vp.IsSet(s) {
		return c.Vp.GetBool(s)
	}
	return def
}
