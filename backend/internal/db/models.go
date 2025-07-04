package db

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Name        string
	DiscordTag  string
	DiscordID   string `gorm:"uniqueIndex"`
	GDUserID    *int32
	GDUser      *GDUser      `gorm:"foreignKey:GDUserID;references:ID"`
	Completions []Completion `gorm:"foreignKey:Victor"`
	Tokens      []Token      `gorm:"foreignKey:UserID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type GDUser struct {
	ID            int64 `gorm:"primaryKey;uniqueIndex"`
	Name          string
	CreatedLevels []Level `gorm:"foreignKey:CreatedByID"`
	Stars         int32
	BeatenLevels  LevelCount `gorm:"type:json"`
	Demons        DemonCount `gorm:"type:json"`
	SecretCoins   int32
	UserCoins     int32
	Icons         IconSet `gorm:"type:json"`
}

type Level struct {
	ID              uint64 `gorm:"primaryKey;uniqueIndex"`
	Name            string
	Description     string
	CreatedBy       GDUser       `gorm:"foreignKey:CreatedByID;references:ID"`
	CreatedByID     uint64       `gorm:"index"`
	Completions     []Completion `gorm:"foreignKey:LevelID"`
	Downloads       uint64
	Likes           int64
	Version         uint16
	Length          LevelLength
	FeatureScore    int32
	Rated           GDRated
	Difficulty      GDDifficulty
	DemonDifficulty GDDemonDifficulty
	Coins           uint8
	VerifiedCoins   bool
	GDDLRating      *uint8
	GDDLEnjoyment   *uint8
	DLPlacement     *uint32
	AREDLPlacement  *uint32
	IDLPlacement    *uint32
	NLWTier         *NLWTier
	IDSTier         *IDSTier
	GDDPTier        *GDDPTier
}

type Completion struct {
	ID                     uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Victor                 uuid.UUID `gorm:"type:uuid;index"`
	LevelID                int32     `gorm:"index"`
	Level                  Level     `gorm:"foreignKey:LevelID;references:ID"`
	Verified               bool
	ReviewedBy             *uuid.UUID
	ReviewedByUser         *User `gorm:"foreignKey:ReviewedBy;references:ID"`
	Proof                  string
	SubmittedGDDLRating    *uint8
	SubmittedGDDLEnjoyment *uint8
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type Token struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID      uuid.UUID `gorm:"type:uuid;index"`
	AppName     string
	Permissions *string
	Value       string
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ===== USER INFO =====
type LevelCount struct {
	Auto   int32
	Easy   int32
	Normal int32
	Hard   int32
	Harder int32
	Insane int32
	Total  int32
}

func (c LevelCount) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c *LevelCount) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("Type assertion failed!")
	}
	return json.Unmarshal(b, &c)
}

type DemonCount struct {
	Easy    int32
	Medium  int32
	Hard    int32
	Insane  int32
	Extreme int32
	Total   int32
}

func (c DemonCount) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c *DemonCount) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("Type assertion failed!")
	}
	return json.Unmarshal(b, &c)
}

type IconSet struct {
	Color     int32
	Color2    int32
	ColorGlow int32
	Icon      int32
	Ship      int32
	Ball      int32
	Wave      int32
	Robot     int32
	Spider    int32
	Swing     int32
	Streak    int32
	Glow      int32
}

func (s IconSet) Value() (driver.Value, error) {
	return json.Marshal(s)
}

func (s *IconSet) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("Type assertion failed!")
	}
	return json.Unmarshal(b, &s)
}

// ===== LEVEL ENUMS =====
type GDDifficulty uint8

const (
	GDUnknownDiff GDDifficulty = iota
	GDAuto
	GDEasy
	GDNormal
	GDHard
	GDHarder
	GDInsane
)

func (d GDDifficulty) String() string {
	switch d {
	case GDUnknownDiff:
		return "Unknown"
	case GDAuto:
		return "Auto"
	case GDEasy:
		return "Easy"
	case GDNormal:
		return "Normal"
	case GDHard:
		return "Hard"
	case GDHarder:
		return "Harder"
	case GDInsane:
		return "Insane"
	}
	return "Unknown"
}

type GDDemonDifficulty uint8

const (
	GDNonDemon GDDemonDifficulty = iota
	GDEasyDemon
	GDMediumDemon
	GDHardDemon
	GDInsaneDemon
	GDExtremeDemon
)

func (d GDDemonDifficulty) String() string {
	switch d {
	case GDNonDemon:
		return "Non-Demon"
	case GDEasyDemon:
		return "Easy Demon"
	case GDMediumDemon:
		return "Medium Demon"
	case GDHardDemon:
		return "Hard Demon"
	case GDInsaneDemon:
		return "Insane Demon"
	case GDExtremeDemon:
		return "Extreme Demon"
	}
	return "Unknown"
}

type LevelLength uint8

const (
	LengthUnknown LevelLength = iota
	LengthTiny
	LengthShort
	LengthMedium
	LengthLong
	LengthXL
)

func (l LevelLength) String() string {
	switch l {
	case LengthTiny:
		return "Tiny"
	case LengthShort:
		return "Short"
	case LengthMedium:
		return "Medium"
	case LengthLong:
		return "Long"
	case LengthXL:
		return "XL"
	}
	return "Unknown"
}

type GDRated uint8

const (
	GDUnknownRate GDRated = iota
	GDUnrated
	GDFeatured
	GDEpic
	GDLegendary
	GDMythic
)

func (r GDRated) String() string {
	switch r {
	case GDUnrated:
		return "Unrated"
	case GDFeatured:
		return "Featured"
	case GDEpic:
		return "Epic"
	case GDLegendary:
		return "Legendary"
	case GDMythic:
		return "Mythic"
	}
	return "Unknown"
}

type NLWTier uint8

const (
	NLWNone NLWTier = iota
	NLWFuck
	NLWBeginner
	NLWEasy
	NLWMedium
	NLWHard
	NLWVeryHard
	NLWInsane
	NLWExtreme
	NLWRemorseless
	NLWRelentless
	NLWTerrifying
)

func (t NLWTier) String() string {
	switch t {
	case NLWNone:
		return "None"
	case NLWFuck:
		return "Fuck"
	case NLWBeginner:
		return "Beginner"
	case NLWEasy:
		return "Easy"
	case NLWMedium:
		return "Medium"
	case NLWHard:
		return "Hard"
	case NLWVeryHard:
		return "Very Hard"
	case NLWInsane:
		return "Insane"
	case NLWExtreme:
		return "Extreme"
	case NLWRemorseless:
		return "Remorseles"
	case NLWRelentless:
		return "Relentless"
	case NLWTerrifying:
		return "Terrifying"
	}
	return "Unknown"
}

type IDSTier uint8

const (
	IDSNone IDSTier = iota
	IDSFuck
	IDSSuperBeginner
	IDSBeginner
	IDSEasy
	IDSMedium
	IDSHard
	IDSVeryHard
	IDSInsane
	IDSExtreme
)

type GDDPTier uint8

func (t IDSTier) String() string {
	switch t {
	case IDSNone:
		return "None"
	case IDSFuck:
		return "Fuck"
	case IDSSuperBeginner:
		return "Super Beginner"
	case IDSBeginner:
		return "Beginner"
	case IDSEasy:
		return "Easy"
	case IDSMedium:
		return "Medium"
	case IDSHard:
		return "Hard"
	case IDSVeryHard:
		return "Very Hard"
	case IDSInsane:
		return "Insane"
	case IDSExtreme:
		return "Extreme"
	}
	return "Unknown"
}

const (
	GDDPNone GDDPTier = iota
	GDDPBeginner
	GDDPBronze
	GDDPSilver
	GDDPGold
	GDDPAmber
	GDDPPlatinum
	GDDPSapphire
	GDDPJade
	GDDPEmerald
	GDDPRuby
	GDDPDiamond
	GDDPPearl
	GDDPOnyx
	GDDPAmethyst
	GDDPAzurite
	GDDPObsidian
)

func (t GDDPTier) String() string {
	switch t {
	case GDDPNone:
		return "None"
	case GDDPBeginner:
		return "Beginner"
	case GDDPBronze:
		return "Bronze"
	case GDDPSilver:
		return "Silver"
	case GDDPGold:
		return "Gold"
	case GDDPAmber:
		return "Amber"
	case GDDPPlatinum:
		return "Platinum"
	case GDDPSapphire:
		return "Sapphire"
	case GDDPJade:
		return "Jade"
	case GDDPEmerald:
		return "Emerald"
	case GDDPRuby:
		return "Ruby"
	case GDDPDiamond:
		return "Diamond"
	case GDDPPearl:
		return "Pearl"
	case GDDPOnyx:
		return "Onyx"
	case GDDPAmethyst:
		return "Amethyst"
	case GDDPAzurite:
		return "Azurite"
	case GDDPObsidian:
		return "Obsidian"
	}
	return "Unknown"
}
