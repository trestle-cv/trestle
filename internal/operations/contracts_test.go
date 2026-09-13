package operations
import("testing";"github.com/gantry-tools/gantry-core/contracttest")
func TestAdoptionContract(t *testing.T){if err:=contracttest.Require(AdoptionManifest());err!=nil{t.Fatal(err)}}
