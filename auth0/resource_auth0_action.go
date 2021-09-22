package auth0

import (
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newAction() *schema.Resource {
	return &schema.Resource{

		Create: createAction,
		Read:   readAction,
		Update: updateAction,
		Delete: deleteAction,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validateActionNameFunc(),
				Description:  "The name of an action.",
			},
			"dependencies": {
				Type:        schema.TypeMap,
				Elem:        schema.TypeString,
				Optional:    true,
				Description: "The list of third party npm modules, and their versions, that this action depends on.",
			},
			"code": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The source code of the action.",
			},
			"runtime": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Node runtime. For example: node12, defaults to node12",
			},
			"supported_triggers": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"post-login",
					"credentials-exchange",
					"pre-user-registration",
					"post-user-registration",
					"post-change-password",
					"send-phone-message",
					"iga-fulfillment-execution",
					"iga-fulfillment-assignment",
					"iga-approval",
					"iga-certification",
				}, false),
				Description: "The list of triggers that this action supports. At this time, an action can only target a single trigger at a time.",
			},
			"secrets": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "The list of secrets that are included in an action or a version of an action.",
				Elem:        schema.TypeString,
			},
		},
	}
}

func createAction(d *schema.ResourceData, m interface{}) error {
	c := buildAction(d)
	api := m.(*management.Management)
	if err := api.Hook.Create(c); err != nil {
		return err
	}
	d.SetId(auth0.StringValue(c.ID))
	if err := upsertActionSecrets(d, m); err != nil {
		return err
	}
	return readAction(d, m)
}

func readAction(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	c, err := api.Hook.Read(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return err
	}

	d.Set("name", c.Name)
	d.Set("dependencies", c.Dependencies)
	d.Set("script", c.Script)
	d.Set("trigger_id", c.TriggerID)
	d.Set("enabled", c.Enabled)
	return nil
}

func updateAction(d *schema.ResourceData, m interface{}) error {
	c := buildAction(d)
	api := m.(*management.Management)
	err := api.Hook.Update(d.Id(), c)
	if err != nil {
		return err
	}
	if err = upsertActionSecrets(d, m); err != nil {
		return err
	}
	return readAction(d, m)
}

func upsertActionSecrets(d *schema.ResourceData, m interface{}) error {
	if d.IsNewResource() || d.HasChange("secrets") {
		secrets := Map(d, "secrets")
		api := m.(*management.Management)
		hookSecrets := toActionSecrets(secrets)
		return api.Hook.ReplaceSecrets(d.Id(), hookSecrets)
	}
	return nil
}

func toActionSecrets(val map[string]interface{}) management.HookSecrets {
	hookSecrets := management.HookSecrets{}
	for key, value := range val {
		if strVal, ok := value.(string); ok {
			hookSecrets[key] = strVal
		}
	}
	return hookSecrets
}

func deleteAction(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	err := api.Hook.Delete(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return err
	}
	return err
}

func buildAction(d *schema.ResourceData) *management.Hook {
	h := &management.Hook{
		Name:      String(d, "name"),
		Script:    String(d, "script"),
		TriggerID: String(d, "trigger_id", IsNewResource()),
		Enabled:   Bool(d, "enabled"),
	}

	deps := Map(d, "dependencies")
	if deps != nil {
		h.Dependencies = &deps
	}

	return h
}

func validateActionNameFunc() schema.SchemaValidateFunc {
	return validation.StringMatch(
		regexp.MustCompile("^[^\\s-][\\w -]+[^\\s-]$"),
		"Can only contain alphanumeric characters, spaces and '-'. Can neither start nor end with '-' or spaces.")
}
