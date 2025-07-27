package logger

import (
	"io"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

type Config struct {
	Level       string `json:"level"`
	Format      string `json:"format"`
	File        string `json:"file"`
	Console     bool   `json:"console"`
	PrettyPrint bool   `json:"pretty_print"`
}

// NewLogger creates a new logger instance with JSON output
func NewLogger(config Config) (*Logger, error) {
	log := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Configure JSON formatter
	if config.Format == "json" {
		formatter := &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			PrettyPrint:     config.PrettyPrint,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		}
		log.SetFormatter(formatter)
	}

	// Set up output destinations
	var writers []io.Writer

	// Console output
	if config.Console {
		writers = append(writers, os.Stdout)
	}

	// File output
	if config.File != "" {
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(config.File), 0755); err != nil {
			return nil, err
		}

		file, err := os.OpenFile(config.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		writers = append(writers, file)
	}

	// Set multi-writer if we have multiple outputs
	if len(writers) > 1 {
		log.SetOutput(io.MultiWriter(writers...))
	} else if len(writers) == 1 {
		log.SetOutput(writers[0])
	}

	return &Logger{log}, nil
}

// Structured logging methods for IDS-specific events
func (l *Logger) PacketCaptured(interfaceName string, packetCount int64) {
	l.WithFields(logrus.Fields{
		"component":    "capture",
		"interface":    interfaceName,
		"packet_count": packetCount,
		"event_type":   "packet_captured",
	}).Info("Packet captured successfully")
}

func (l *Logger) AlertGenerated(alertID, ruleID, sourceIP string, severity string) {
	l.WithFields(logrus.Fields{
		"component":  "alerting",
		"alert_id":   alertID,
		"rule_id":    ruleID,
		"source_ip":  sourceIP,
		"severity":   severity,
		"event_type": "alert_generated",
	}).Warn("Security alert generated")
}

func (l *Logger) ConfigLoaded(configFile string) {
	l.WithFields(logrus.Fields{
		"component":   "config",
		"config_file": configFile,
		"event_type":  "config_loaded",
	}).Info("Configuration loaded successfully")
}

func (l *Logger) DetectionEngineStarted(engineType string) {
	l.WithFields(logrus.Fields{
		"component":   "detector",
		"engine_type": engineType,
		"event_type":  "engine_started",
	}).Info("Detection engine started")
}

func (l *Logger) InterfaceStarted(interfaceName string) {
	l.WithFields(logrus.Fields{
		"component":  "capture",
		"interface":  interfaceName,
		"event_type": "interface_started",
	}).Info("Network interface monitoring started")
}

func (l *Logger) SessionTracked(sessionID, sourceIP, destIP string, protocol string) {
	l.WithFields(logrus.Fields{
		"component":  "analyzer",
		"session_id": sessionID,
		"source_ip":  sourceIP,
		"dest_ip":    destIP,
		"protocol":   protocol,
		"event_type": "session_tracked",
	}).Debug("Network session tracked")
}

func (l *Logger) DetectionTriggered(ruleName, sourceIP string, severity string, details map[string]any) {
	fields := logrus.Fields{
		"component":  "detector",
		"rule_name":  ruleName,
		"source_ip":  sourceIP,
		"severity":   severity,
		"event_type": "detection_triggered",
	}

	// Add additional details
	maps.Copy(fields, details)

	l.WithFields(fields).Warn("Detection rule triggered")
}

func (l *Logger) StatisticsUpdate(component string, stats map[string]any) {
	fields := logrus.Fields{
		"component":  component,
		"event_type": "statistics_update",
	}

	// Add statistics
	maps.Copy(fields, stats)

	l.WithFields(fields).Info("Statistics updated")
}

func (l *Logger) ErrorOccurred(component, operation string, err error) {
	l.WithFields(logrus.Fields{
		"component":  component,
		"operation":  operation,
		"error":      err.Error(),
		"event_type": "error_occurred",
	}).Error("Operation failed")
}

func (l *Logger) PerformanceMetric(component, metric string, value any, unit string) {
	l.WithFields(logrus.Fields{
		"component":    component,
		"metric_name":  metric,
		"metric_value": value,
		"unit":         unit,
		"event_type":   "performance_metric",
	}).Debug("Performance metric recorded")
}
