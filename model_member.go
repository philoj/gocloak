package gocloak

// MembershipType type of membership
type MembershipType string // TODO type unclear from docs

// MemberRepresentation membership of a user in an organization
type MemberRepresentation struct {
	ID                         *string                            `json:"id,omitempty"`
	Username                   *string                            `json:"username,omitempty"`
	FirstName                  *string                            `json:"firstName,omitempty"`
	LastName                   *string                            `json:"lastName,omitempty"`
	Email                      *string                            `json:"email,omitempty"`
	EmailVerified              *bool                              `json:"emailVerified,omitempty"`
	Attributes                 *map[string][]string               `json:"attributes,omitempty"`
	UserProfileMetadata        *UserProfileMetadata               `json:"userProfileMetadata,omitempty"`
	Self                       *string                            `json:"self,omitempty"`
	Origin                     *string                            `json:"origin,omitempty"`
	CreatedTimestamp           *int64                             `json:"createdTimestamp,omitempty"`
	Enabled                    *bool                              `json:"enabled,omitempty"`
	TOTP                       *bool                              `json:"totp,omitempty"`
	FederationLink             *string                            `json:"federationLink,omitempty"`
	ServiceAccountClientID     *string                            `json:"serviceAccountClientId,omitempty"`
	Credentials                *[]CredentialRepresentation        `json:"credentials,omitempty"`
	DisableableCredentialTypes *[]any                             `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            *[]string                          `json:"requiredActions,omitempty"`
	FederatedIdentities        *[]FederatedIdentityRepresentation `json:"federatedIdentities,omitempty"`
	RealmRoles                 *[]string                          `json:"realmRoles,omitempty"`
	ClientRoles                *map[string][]string               `json:"clientRoles,omitempty"`
	ClientConsents             *[]UserConsentRepresentation       `json:"clientConsents,omitempty"`
	NotBefore                  *int32                             `json:"notBefore,omitempty"`
	ApplicationRoles           *map[string][]string               `json:"applicationRoles,omitempty"`
	SocialLinks                *[]SocialLinkRepresentation        `json:"socialLinks,omitempty"`
	Groups                     *[]string                          `json:"groups,omitempty"`
	Access                     *map[string]bool                   `json:"access,omitempty"`
	MembershipType             *MembershipType                    `json:"membershipType,omitempty"`
}

func (v *MemberRepresentation) String() string { return prettyStringStruct(v) }

// UserProfileMetadata User profile metadata
type UserProfileMetadata struct {
	Attributes *[]UserProfileAttributeMetadata      `json:"attributes,omitempty"`
	Groups     *[]UserProfileAttributeGroupMetadata `json:"groups,omitempty"`
}

func (v *UserProfileMetadata) String() string { return prettyStringStruct(v) }

// UserProfileAttributeMetadata User profile attribute metadata
type UserProfileAttributeMetadata struct {
	Name        *string                    `json:"name,omitempty"`
	DisplayName *string                    `json:"displayName,omitempty"`
	Required    *bool                      `json:"required,omitempty"`
	ReadOnly    *bool                      `json:"readOnly,omitempty"`
	Annotations *map[string]any            `json:"annotations,omitempty"` // TODO any?
	Validators  *map[string]map[string]any `json:"validators,omitempty"`  // TODO any?
	Group       *string                    `json:"group,omitempty"`
	MultiValued *bool                      `json:"multiValued,omitempty"`
}

func (v *UserProfileAttributeMetadata) String() string { return prettyStringStruct(v) }

// UserProfileAttributeGroupMetadata User profile attribute group metadata
type UserProfileAttributeGroupMetadata struct {
	Name               *string         `json:"name,omitempty"`
	DisplayHeader      *string         `json:"displayHeader,omitempty"`
	DisplayDescription *string         `json:"displayDescription,omitempty"`
	Annotations        *map[string]any `json:"annotations,omitempty"` // TODO any?
}

func (v *UserProfileAttributeGroupMetadata) String() string { return prettyStringStruct(v) }

// UserConsentRepresentation User consent
type UserConsentRepresentation struct {
	ClientID            *string   `json:"clientId,omitempty"`
	GrantedClientScopes *[]string `json:"grantedClientScopes,omitempty"`
	CreatedDate         *int64    `json:"createdDate,omitempty"`
	LastUpdatedDate     *int64    `json:"lastUpdatedDate,omitempty"`
	GrantedRealmRoles   *[]string `json:"grantedRealmRoles,omitempty"`
}

func (v *UserConsentRepresentation) String() string { return prettyStringStruct(v) }

// SocialLinkRepresentation User social link
type SocialLinkRepresentation struct {
	SocialProvider *string `json:"socialProvider,omitempty"`
	SocialUserID   *string `json:"socialUserId,omitempty"`
	SocialUsername *string `json:"socialUsername,omitempty"`
}

func (v *SocialLinkRepresentation) String() string { return prettyStringStruct(v) }

type GetOrganizationMembersParams struct {
	// TODO
}
