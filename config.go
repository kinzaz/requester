package requester

import (
	"errors"
	"fmt"
	"time"
)

type (
	Config struct {
		QueryTimeout             time.Duration `yaml:"queryTimeout"`
		IdleConnTimeout          time.Duration `yaml:"idleConnTimeout"`
		MaxIdleConns             int           `yaml:"maxIdleConns"`
		EnableMetrics            bool          `yaml:"enableMetrics"`
		DefaultClientsCount      int           `yaml:"defaultClientsCount"`
		ClientsRefreshTimeout    time.Duration `yaml:"clientsRefreshTimeout"`
		PreserveClientsOnRefresh bool          `yaml:"preserveClientsOnRefresh"`
		TorProxy                 string        `yaml:"torProxy"`
		EnableApifyUAs           bool          `yaml:"enableApifyUAs"`
		RandomizeRoundrobinStart bool          `yaml:"randomizeRoundrobinStart"`

		Trottler struct {
			Enabled                        bool          `yaml:"enabled"`
			PerClient                      bool          `yaml:"perClient"`
			WaitClientTimeout              time.Duration `yaml:"waitClientTimeout"`
			IdleTimeout                    time.Duration `yaml:"idleTimeout"`
			MinRPS                         int           `yaml:"minRPS"`
			MaxRPS                         int           `yaml:"maxRPS"`
			IncRPS                         int           `yaml:"incRPS"`
			DecRPS                         int           `yaml:"decRPS"`
			ManualMode                     bool          `yaml:"manualMode"`
			LapsWithoutFailsBeforeIncrease int           `yaml:"lapsWithoutFailsBeforeIncrease"`
			SuccessBeforeIncrease          int           `yaml:"successBeforeIncrease"`
			FailsBeforeDecrease            int           `yaml:"failsBeforeDecrease"`
			BanDomains                     struct {
				Enabled        bool          `yaml:"enabled"`
				Duration       time.Duration `yaml:"duration"`
				FailsBeforeBan int           `yaml:"failsBeforeBan"`
				WaitForUnban   bool          `yaml:"waitForUnban"`
			} `yaml:"banDomains"`
		} `yaml:"trottler"`

		Captcha struct {
			Enabled bool `yaml:"enabled"`
			Solver  struct {
				Host    string        `yaml:"host"`
				Port    int           `yaml:"port"`
				Timeout time.Duration `yaml:"timeout"`
			} `yaml:"solver"`
			Attempts int `yaml:"attempts"`
		} `yaml:"captcha"`

		Proxy struct {
			Enabled bool          `yaml:"enabled"`
			Host    string        `yaml:"host"`
			Port    int           `yaml:"port"`
			Timeout time.Duration `yaml:"timeout"`
			List    string        `yaml:"list"`
		} `yaml:"proxy"`

		Cycletls struct {
			Enabled   bool   `yaml:"enabled"`
			Randomize bool   `yaml:"randomize"`
			Ja3       string `yaml:"ja3"`
			UA        string `yaml:"ua"`
		} `yaml:"cycletls"`
	}
)

func (c *Config) Validate() error {
	if c.QueryTimeout == 0 {
		return errors.New("queryTimeout is empty")
	}
	if c.Trottler.Enabled {
		if c.Trottler.WaitClientTimeout == 0 {
			return errors.New("trottler.WaitClientTimeout is empty")
		}
		if c.Trottler.IdleTimeout == 0 {
			return errors.New("trottler.IdleTimeout is empty")
		}
		if c.Trottler.MinRPS < 1 {
			return errors.New("trottler.minRPS less than 1")
		}
		if c.Trottler.MaxRPS < 1 {
			return errors.New("trottler.maxRPS less than 1")
		}
		if c.Trottler.IncRPS < 1 {
			return errors.New("trottler.incRPS less than 1")
		}
		if c.Trottler.DecRPS < 1 {
			return errors.New("trottler.decRPS less than 1")
		}
		if c.Trottler.SuccessBeforeIncrease < 1 {
			return errors.New("trottler.successBeforeIncrease less than 1")
		}
		if c.Trottler.FailsBeforeDecrease < 1 {
			return errors.New("trottler.failsBeforeDecrease less than 1")
		}
		if c.Trottler.BanDomains.Enabled {
			if c.Trottler.BanDomains.Duration == 0 {
				return errors.New("trottler.banDomains.Duration is empty")
			}
			if c.Trottler.BanDomains.FailsBeforeBan == 0 {
				return errors.New("trottler.banDomains.failsBeforeBan is empty")
			}
		}
	}

	if c.DefaultClientsCount < 1 {
		return errors.New("defaultClientsCount less than 1")
	}
	if c.ClientsRefreshTimeout == 0 {
		return errors.New("clientsRefreshTimeout is empty")
	}

	if c.MaxIdleConns == 0 {
		return errors.New("maxIdleConns is empty")
	}
	if c.IdleConnTimeout == 0 {
		return errors.New("idleConnTimeout is empty")
	}

	if c.Proxy.Enabled {
		if c.Proxy.Host == "" {
			return errors.New("proxy.host is empty")
		}
		if c.Proxy.Port < 1 {
			return errors.New("proxy.port is empty or less than 1")
		}
		if c.Proxy.Timeout < time.Second*1 {
			return errors.New("proxy.timeout is empty or less than 1s")
		}
		if c.Proxy.List == "" {
			return errors.New("proxy.list is empty")
		}
	}

	if c.Captcha.Enabled {
		if c.Captcha.Solver.Host == "" {
			return fmt.Errorf("solver.host is empty")
		}
		if c.Captcha.Solver.Port == 0 {
			return fmt.Errorf("solver.port is empty")
		}
		if c.Captcha.Solver.Timeout == 0 {
			return fmt.Errorf("solver.tiomeout is empty")
		}
	}

	if c.Cycletls.Enabled {
		if !c.Cycletls.Randomize {
			if c.Cycletls.Ja3 == "" {
				return fmt.Errorf("cycletls.ja3 is empty")
			}
			if c.Cycletls.UA == "" {
				return fmt.Errorf("cycletls.ua is empty")
			}
		}
	}

	return nil
}
