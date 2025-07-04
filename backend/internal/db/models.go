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
	DiscordID   string    `gorm:"uniqueIndex"`
	GDUserID    *int32
	GDUser      *GDUser      `gorm:"foreignKey:GDUserID;references:ID"`
	Completions []Completion `gorm:"foreignKey:Victor"`
	Tokens      []Token      `gorm:"foreignKey:UserID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type GDUser struct {
	ID            int32 `gorm:"primaryKey;uniqueIndex"`
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
	ID              int32 `gorm:"primaryKey;uniqueIndex"`
	Name            string
	Description     string
	CreatedBy       GDUser       `gorm:"foreignKey:CreatedByID;references:ID"`
	CreatedByID     int32        `gorm:"index"`
	Completions     []Completion `gorm:"foreignKey:LevelID"`
	Downloads       int32
	Likes           int32
	Version         int32
	Length          int32
	FeatureScore    int32
	Rated           GDRated
	Difficulty      GDDifficulty
	DemonDifficulty GDDemonDifficulty
	Coins           int32
	VerifiedCoins   bool
	GDDLRating      *int32
	GDDLEnjoyment   *int32
	AREDLPlacement  *int32
	DLPlacement     *int32
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
	CheckedBy              *uuid.UUID
	CheckedByUser          *User `gorm:"foreignKey:CheckedBy;references:ID"`
	Proof                  string
	SubmittedGDDLRating    *int32
	SubmittedGDDLEnjoyment *int32
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
type GDDifficulty int8
type GDDemonDifficulty int8
type GDRated int8
type NLWTier int8
type IDSTier int8
type GDDPTier int8

const (
	GDUnknownDiff GDDifficulty = iota
	GDAuto
	GDEasy
	GDNormal
	GDHard
	GDHarder
	GDInsane
)

const (
	GDNonDemon GDDemonDifficulty = iota
	GDEasyDemon
	GDMediumDemon
	GDHardDemon
	GDInsaneDemon
	GDExtremeDemon
)

const (
	GDUnknownRate GDRated = iota
	GDUnrated
	GDFeatured
	GDEpic
	GDLegendary
	GDMythic
)

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

func (r GDRated) String() string {
	switch r {
	case GDUnknownRate:
		return "Unknown"
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
