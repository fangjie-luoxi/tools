package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Log *zap.SugaredLogger

// Setup 初始化日志 fileName 文件路径 默认: "./static/logs/error/log.log"
func Setup(fileName string) *zap.SugaredLogger {
	writeSyncer := getWriteSyncer(fileName)
	encoder := getEncoder()
	core := zapcore.NewCore(encoder, writeSyncer, zapcore.DebugLevel)
	logger := zap.New(core, zap.AddCaller())
	return logger.Sugar()
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getWriteSyncer(fileName string) zapcore.WriteSyncer {
	if fileName == "" {
		fileName = "./static/logs/error/log.log"
	}
	lumberJackLogger := NewLogIO(fileName)
	return zapcore.AddSync(lumberJackLogger)
}

func NewLogIO(filename string) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   filename, // 日志文件的位置
		MaxSize:    10,       // 在进行切割之前，日志文件的最大大小（以MB为单位）
		MaxBackups: 5,        // 保留旧文件的最大个数
		MaxAge:     30,       // 保留旧文件的最大天数
		Compress:   false,    // 是否压缩/归档旧文件
	}
}
