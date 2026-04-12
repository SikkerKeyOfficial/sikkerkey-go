package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sikkerkey "github.com/sikkerkey/sikkerkey-go"
)

var passed, failed int

func pass(name, detail string) {
	passed++
	if detail != "" {
		fmt.Printf("  PASS  %s — %s\n", name, detail)
	} else {
		fmt.Printf("  PASS  %s\n", name)
	}
}

func fail(name, err string) {
	failed++
	fmt.Printf("  FAIL  %s — %s\n", name, err)
}

func main() {
	vaultID := ""
	projectID := ""
	if len(os.Args) > 1 {
		vaultID = os.Args[1]
	}
	if len(os.Args) > 2 {
		projectID = os.Args[2]
	}

	start := time.Now()

	fmt.Println("SikkerKey Go SDK Test")
	fmt.Println("=====================")
	fmt.Println()

	// ── 1. Identity ──

	var sk *sikkerkey.Client
	var err error
	if vaultID != "" {
		sk, err = sikkerkey.New(vaultID)
	} else {
		sk, err = sikkerkey.NewAutoDetect()
	}
	if err != nil {
		fail("Identity load", err.Error())
		fmt.Println("\nCannot continue without identity.")
		os.Exit(1)
	}
	pass("Identity load", fmt.Sprintf("machine=%s, vault=%s", sk.MachineID(), sk.VaultID()))

	// ── 2. List vaults ──

	vaults := sikkerkey.ListVaults()
	pass("ListVaults", fmt.Sprintf("%d vault(s): %s", len(vaults), strings.Join(vaults, ", ")))

	// ── 3. List secrets ──

	secrets, err := sk.ListSecrets()
	if err != nil {
		fail("ListSecrets", err.Error())
	} else {
		pass("ListSecrets", fmt.Sprintf("%d secrets", len(secrets)))
	}

	// ── 4. List by project ──

	testProjectID := projectID
	if testProjectID == "" && len(secrets) > 0 && secrets[0].ProjectID != nil {
		testProjectID = *secrets[0].ProjectID
	}
	if testProjectID != "" {
		projectSecrets, err := sk.ListSecretsByProject(testProjectID)
		if err != nil {
			fail("ListSecretsByProject", err.Error())
		} else {
			pass("ListSecretsByProject", fmt.Sprintf("%d secrets in %s", len(projectSecrets), testProjectID))
		}
	} else {
		fail("ListSecretsByProject", "no project ID available")
	}

	// ── 5. Get secret ──

	var existingSimple *sikkerkey.SecretListItem
	var existingStructured *sikkerkey.SecretListItem
	for i := range secrets {
		if secrets[i].FieldNames == nil && existingSimple == nil {
			existingSimple = &secrets[i]
		}
		if secrets[i].FieldNames != nil && existingStructured == nil {
			existingStructured = &secrets[i]
		}
	}

	if existingSimple != nil {
		value, err := sk.GetSecret(existingSimple.ID)
		if err != nil {
			fail("GetSecret", err.Error())
		} else {
			pass("GetSecret", fmt.Sprintf("%d chars from %s", len(value), existingSimple.Name))
		}
	} else {
		pass("GetSecret", "skipped — no simple secret available")
	}

	// ── 6. Get fields ──

	if existingStructured != nil {
		fields, err := sk.GetFields(existingStructured.ID)
		if err != nil {
			fail("GetFields", err.Error())
		} else {
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			pass("GetFields", fmt.Sprintf("%d fields: %s", len(fields), strings.Join(keys, ", ")))
		}

		// ── 7. Get field ──
		fields, err = sk.GetFields(existingStructured.ID)
		if err == nil && len(fields) > 0 {
			var firstKey string
			for k := range fields {
				firstKey = k
				break
			}
			val, err := sk.GetField(existingStructured.ID, firstKey)
			if err != nil {
				fail("GetField", err.Error())
			} else {
				display := val
				if len(display) > 20 {
					display = display[:20] + "..."
				}
				pass("GetField", fmt.Sprintf("%s = %s", firstKey, display))
			}
		}

		// ── 8. Get field — not found ──
		_, err = sk.GetField(existingStructured.ID, "nonexistent_field_xyz")
		if err != nil {
			pass("GetField (not found)", "correctly returned error")
		} else {
			fail("GetField (not found)", "should have returned error")
		}
	} else {
		pass("GetFields", "skipped — no structured secret available")
		pass("GetField", "skipped")
		pass("GetField (not found)", "skipped")
	}

	// ── 9. Export ──

	exported, err := sk.Export("")
	if err != nil {
		fail("Export", err.Error())
	} else {
		pass("Export", fmt.Sprintf("%d entries", len(exported)))
	}

	if testProjectID != "" {
		exported, err := sk.Export(testProjectID)
		if err != nil {
			fail("Export (project)", err.Error())
		} else {
			pass("Export (project)", fmt.Sprintf("%d entries from %s", len(exported), testProjectID))
		}
	}

	// ── Write tests ──

	if testProjectID == "" {
		fmt.Println("\n  Skipping write tests — no project ID available.")
	} else {
		fmt.Printf("\n  ── Write tests (project: %s) ──\n\n", testProjectID)

		// ── 10. Create simple secret ──
		tempSecretID := ""
		result, err := sk.CreateSecret(testProjectID, "sdk_test_simple_go", &sikkerkey.CreateOpts{
			Note: "Created by Go SDK test",
		})
		if err != nil {
			fail("CreateSecret (simple)", err.Error())
		} else {
			tempSecretID = result.ID
			display := result.Value
			if len(display) > 16 {
				display = display[:16] + "..."
			}
			pass("CreateSecret (simple)", fmt.Sprintf("id=%s, value=%s", result.ID, display))
		}

		if tempSecretID != "" {
			// ── 11. Set secret ──
			err = sk.SetSecret(tempSecretID, "updated-value-go-12345")
			if err != nil {
				fail("SetSecret", err.Error())
			} else {
				readBack, err := sk.GetSecret(tempSecretID)
				if err != nil {
					fail("SetSecret", "readback failed: "+err.Error())
				} else if readBack == "updated-value-go-12345" {
					pass("SetSecret", "value updated and verified")
				} else {
					fail("SetSecret", "readback mismatch: "+readBack)
				}
			}

			// ── 12. Rotate simple ──
			newVal, err := sk.Rotate(tempSecretID, &sikkerkey.GenerateOpts{Length: 24, Charset: "alphanumeric"})
			if err != nil {
				fail("Rotate (simple)", err.Error())
			} else {
				display := newVal
				if len(display) > 16 {
					display = display[:16] + "..."
				}
				pass("Rotate (simple)", fmt.Sprintf("new value: %s (%d chars)", display, len(newVal)))
			}

			// ── 13. Revert ──
			msg, err := sk.RevertSecret(tempSecretID)
			if err != nil {
				fail("RevertSecret", err.Error())
			} else {
				readBack, _ := sk.GetSecret(tempSecretID)
				if readBack == "updated-value-go-12345" {
					pass("RevertSecret", "reverted to previous value")
				} else {
					pass("RevertSecret", "reverted ("+msg+")")
				}
			}

			// ── 14. Delete simple ──
			delMsg, err := sk.DeleteSecret(tempSecretID)
			if err != nil {
				fail("DeleteSecret", err.Error())
			} else {
				pass("DeleteSecret", delMsg)
			}

			// ── 15. Get deleted — should fail ──
			_, err = sk.GetSecret(tempSecretID)
			if err != nil {
				pass("GetSecret (deleted)", "correctly returned error")
			} else {
				fail("GetSecret (deleted)", "should have returned error")
			}
		}

		// ── 16. Create structured secret ──
		tempStructuredID := ""
		structResult, err := sk.CreateSecret(testProjectID, "sdk_test_structured_go", &sikkerkey.CreateOpts{
			Fields: map[string]string{"host": "localhost", "port": "5432", "password": "test123"},
			Note:   "Created by Go SDK test",
		})
		if err != nil {
			fail("CreateSecret (structured)", err.Error())
		} else {
			tempStructuredID = structResult.ID
			pass("CreateSecret (structured)", "id="+structResult.ID)
		}

		if tempStructuredID != "" {
			// ── 17. Set field ──
			err = sk.SetField(tempStructuredID, "password", "new-password-go-xyz")
			if err != nil {
				fail("SetField", err.Error())
			} else {
				readBack, err := sk.GetField(tempStructuredID, "password")
				if err != nil {
					fail("SetField", "readback failed: "+err.Error())
				} else if readBack == "new-password-go-xyz" {
					pass("SetField", "password updated and verified")
				} else {
					fail("SetField", "readback mismatch: "+readBack)
				}
			}

			// ── 18. Rotate fields ──
			updated, err := sk.RotateFields(tempStructuredID, []string{"password"}, &sikkerkey.GenerateOpts{Length: 20, Charset: "alphanumeric"})
			if err != nil {
				fail("RotateFields", err.Error())
			} else {
				display := updated["password"]
				if len(display) > 16 {
					display = display[:16] + "..."
				}
				pass("RotateFields", "password rotated to "+display)
			}

			// ── 19. Rotate simple on structured — should fail ──
			_, err = sk.Rotate(tempStructuredID, nil)
			if err != nil {
				pass("Rotate (structured)", "correctly rejected: "+err.Error())
			} else {
				fail("Rotate (structured)", "should have returned error")
			}

			// ── 20. Delete structured ──
			_, err = sk.DeleteSecret(tempStructuredID)
			if err != nil {
				fail("DeleteSecret (structured)", err.Error())
			} else {
				pass("DeleteSecret (structured)", "cleaned up")
			}
		}
	}

	// ── Summary ──

	_ = json.Marshal // keep import
	elapsed := time.Since(start).Milliseconds()
	fmt.Println()
	fmt.Println("═══════════════════════════")
	fmt.Printf("  %d passed, %d failed (%dms)\n", passed, failed, elapsed)
	fmt.Println("═══════════════════════════")

	if failed > 0 {
		os.Exit(1)
	}
}
