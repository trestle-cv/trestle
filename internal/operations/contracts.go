// Package operations declares Trestle's canonical functional operation surface.
package operations
import ("github.com/gantry-tools/gantry-core/contracttest"; "github.com/gantry-tools/gantry-core/operation")
var Contracts=[]operation.Contract{
	contract("trestle.setup.status",operation.Read,"GET","/admin/v1/setup/status","setup","status",operation.Public,""),
	contract("trestle.setup.apply",operation.Mutation,"POST","/admin/v1/setup","setup","apply",operation.Public,"trestle.setup.applied"),
	contract("trestle.users.manage",operation.Destructive,"POST","/admin/v1/manage/users","users","manage",operation.Capability,"trestle.users.managed"),
}
func contract(id string,kind operation.Kind,method,path,resource,verb string,boundary operation.Boundary,event string) operation.Contract { audit:=operation.Audit{};if kind!=operation.Read{audit=operation.Audit{Required:true,Event:event}};auth:=operation.Authorization{Boundary:boundary};if boundary==operation.Capability{auth.Capability="accounts.manage"};return operation.Contract{SchemaVersion:operation.SchemaVersion,ID:id,Kind:kind,Route:operation.Route{Method:method,Path:path},CLI:&operation.CLI{Resource:resource,Verb:verb},Authorization:auth,Audit:audit,Idempotency:operation.Idempotency{RetrySafe:kind==operation.Read},Automation:operation.Automatable} }
func AdoptionManifest() contracttest.Manifest {routes:=make([]operation.Route,len(Contracts));ids:=make([]string,len(Contracts));for i,c:=range Contracts{routes[i],ids[i]=c.Route,c.ID};return contracttest.Manifest{SchemaVersion:1,Project:"trestle",Operations:Contracts,ObservedRoutes:routes,WebsiteOperations:ids}}
