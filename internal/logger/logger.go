package logger

import (
	"go.uber.org/zap"
)

func NewLogger() *zap.SugaredLogger {
	// For local dev: human-readable logs
	l, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	return l.Sugar()
}
