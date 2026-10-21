package frp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

const profileMetaFileName = "profile.json"

type ProfileInfo struct {
	ID         string
	Name       string
	Configured bool
}

type Catalog struct {
	root string
}

func DefaultCatalog() (*Catalog, error) {
	identityPath, err := clientidentity.DefaultPath()
	if err != nil {
		return nil, err
	}
	return NewCatalog(filepath.Join(filepath.Dir(identityPath), "frp"))
}

func NewCatalog(root string) (*Catalog, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("FRP catalog directory is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve FRP catalog directory: %w", err)
	}
	c := &Catalog{root: filepath.Clean(absolute)}
	if err = c.Ensure(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Catalog) Root() string { return c.root }

func (c *Catalog) Ensure() error {
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return fmt.Errorf("create FRP catalog: %w", err)
	}
	if err := secureDirectory(c.root); err != nil {
		return err
	}
	profiles := filepath.Join(c.root, "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		return fmt.Errorf("create FRP profile directory: %w", err)
	}
	return secureDirectory(profiles)
}

func (c *Catalog) Store(id string) (*Store, error) {
	id = strings.TrimSpace(id)
	if !identifierValid(id) {
		return nil, unsupported("profile id is invalid")
	}
	if id == DefaultProfileID {
		return NewStore(c.root)
	}
	return NewStore(filepath.Join(c.root, "profiles", id))
}

func (c *Catalog) List() ([]ProfileInfo, error) {
	if err := c.Ensure(); err != nil {
		return nil, err
	}
	profiles := []ProfileInfo{}
	defaultInfo := ProfileInfo{ID: DefaultProfileID, Name: "默认穿透服务器"}
	store, err := c.Store(DefaultProfileID)
	if err != nil {
		return nil, err
	}
	if cfg, loadErr := store.Load(); loadErr == nil {
		defaultInfo.Name = cfg.Profile.Name
		defaultInfo.Configured = true
	} else if !errors.Is(loadErr, ErrNoConfig) {
		return nil, loadErr
	}
	profiles = append(profiles, defaultInfo)

	entries, err := os.ReadDir(filepath.Join(c.root, "profiles"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !identifierValid(entry.Name()) {
			continue
		}
		info := ProfileInfo{ID: entry.Name(), Name: entry.Name()}
		store, storeErr := c.Store(entry.Name())
		if storeErr != nil {
			continue
		}
		if cfg, loadErr := store.Load(); loadErr == nil {
			info.Name = cfg.Profile.Name
			info.Configured = true
		} else if !errors.Is(loadErr, ErrNoConfig) {
			continue
		} else if meta, metaErr := loadProfileMeta(store.Root()); metaErr == nil && meta.Name != "" {
			info.Name = meta.Name
		}
		profiles = append(profiles, info)
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		if profiles[i].ID == DefaultProfileID {
			return true
		}
		if profiles[j].ID == DefaultProfileID {
			return false
		}
		return profiles[i].Name < profiles[j].Name
	})
	return profiles, nil
}

func (c *Catalog) Create(id, name string) (ProfileInfo, error) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if !identifierValid(id) {
		return ProfileInfo{}, unsupported("profile id is invalid")
	}
	if id == DefaultProfileID {
		return ProfileInfo{}, unsupported("default profile already exists")
	}
	if name == "" {
		name = "新穿透服务器"
	}
	if err := validateName("profile name", name); err != nil {
		return ProfileInfo{}, err
	}
	store, err := c.Store(id)
	if err != nil {
		return ProfileInfo{}, err
	}
	if err = store.Ensure(); err != nil {
		return ProfileInfo{}, err
	}
	if _, loadErr := store.Load(); loadErr == nil {
		return ProfileInfo{}, unsupported("profile %q already exists", id)
	} else if !errors.Is(loadErr, ErrNoConfig) {
		return ProfileInfo{}, loadErr
	}
	meta := profileMeta{SchemaVersion: SchemaVersion, ID: id, Name: name}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return ProfileInfo{}, err
	}
	if err = writePrivateFile(filepath.Join(store.Root(), profileMetaFileName), append(data, '\n')); err != nil {
		return ProfileInfo{}, err
	}
	return ProfileInfo{ID: id, Name: name}, nil
}

func loadProfileMeta(root string) (profileMeta, error) {
	data, err := os.ReadFile(filepath.Join(root, profileMetaFileName))
	if err != nil {
		return profileMeta{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var meta profileMeta
	if err = decoder.Decode(&meta); err != nil {
		return profileMeta{}, err
	}
	if meta.SchemaVersion != SchemaVersion && meta.SchemaVersion != LegacySchema {
		return profileMeta{}, fmt.Errorf("unsupported profile metadata schema")
	}
	if !identifierValid(meta.ID) {
		return profileMeta{}, fmt.Errorf("invalid profile metadata id")
	}
	return meta, nil
}

type profileMeta struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	Name          string `json:"name"`
}
