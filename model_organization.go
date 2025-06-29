package gocloak

// OrganizationRepresentation Organization
type OrganizationRepresentation struct {
	// ID readonly
	ID                *string                             `json:"id,omitempty"`
	Name              *string                             `json:"name,omitempty"`
	Alias             *string                             `json:"alias,omitempty"`
	Enabled           *bool                               `json:"enabled,omitempty"`
	Description       *string                             `json:"description,omitempty"`
	RedirectURL       *string                             `json:"redirectUrl,omitempty"`
	Attributes        *map[string][]string                `json:"attributes,omitempty"`
	Domains           *[]OrganizationDomainRepresentation `json:"domains,omitempty"`
	Members           *[]MemberRepresentation             `json:"members,omitempty"`
	IdentityProviders *[]IdentityProviderRepresentation   `json:"identityProviders,omitempty"`
}

func (v *OrganizationRepresentation) String() string { return prettyStringStruct(v) }

// OrganizationDomainRepresentation Organization domain
type OrganizationDomainRepresentation struct {
	Name     *string `json:"name,omitempty"`
	Verified *bool   `json:"verified,omitempty"`
}

func (v *OrganizationDomainRepresentation) String() string { return prettyStringStruct(v) }

type GetOrganizationsParams struct {
	// BriefRepresentation defaults to false
	// The meaning is counter-intuitive: If set to true, will get the non-brief(detailed) response
	BriefRepresentation *bool `json:"briefRepresentation,string,omitempty"`

	// Search in name or domain
	Search *string `json:"search,omitempty"`
	// Exact match the search query
	Exact *bool `json:"exact,string,omitempty"`

	// First skips first N entries (pagination)
	First *int `json:"first,omitempty"`
	// Max limits the page size
	Max *int `json:"max,omitempty"`

	// Q Query custom attributes, in the format 'key1:value2 key2:value2'
	Q *string `json:"q,omitempty"`
}
