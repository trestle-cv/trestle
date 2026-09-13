package cluster

import (
    "context"
    "path/filepath"
    "testing"
    "time"

    core "github.com/gantry-tools/gantry-core/cluster"
    "github.com/trestle-cv/trestle/internal/store"
)

func openTest(t *testing.T) (*store.Store,*Service) { t.Helper(); s,err:=store.Open(context.Background(),filepath.Join(t.TempDir(),"data")); if err!=nil{t.Fatal(err)}; t.Cleanup(func(){s.Close()}); return s,New(s.DB()) }
func TestIdentityPersists(t *testing.T){ _,svc:=openTest(t); ctx:=context.Background(); a,err:=svc.EnsureIdentity(ctx,"test");if err!=nil{t.Fatal(err)};b,err:=svc.EnsureIdentity(ctx,"test");if err!=nil{t.Fatal(err)};if a.NodeID!=b.NodeID||a.InstallationID!=b.InstallationID{t.Fatal("identity changed")}}
func TestInviteIsSingleUseAndMembershipLifecycle(t *testing.T){ _,host:=openTest(t);_,remote:=openTest(t);ctx:=context.Background();ri,err:=remote.UpdateIdentity(ctx,"remote","https://remote.example","test");if err!=nil{t.Fatal(err)};inv,token,err:=host.Invite(ctx);if err!=nil||inv.State!=core.PairingPending{t.Fatal(err)};bundle,err:=host.Pair(ctx,token,ri);if err!=nil{t.Fatal(err)};if bundle.Credential==""{t.Fatal("missing credential")};if _,err=host.Pair(ctx,token,ri);err==nil{t.Fatal("invitation replay accepted")};ms,err:=host.Members(ctx);if err!=nil||len(ms)!=1{t.Fatalf("members=%v err=%v",len(ms),err)};if err=host.SetEnabled(ctx,ri.NodeID,false);err!=nil{t.Fatal(err)};if err=host.SetEnabled(ctx,ri.NodeID,true);err!=nil{t.Fatal(err)};if _,err=host.Rotate(ctx,ri.NodeID);err!=nil{t.Fatal(err)};if err=host.Revoke(ctx,ri.NodeID);err!=nil{t.Fatal(err)};if err=host.Remove(ctx,ri.NodeID);err!=nil{t.Fatal(err)}}
func TestThreeNodeAggregatePreservesOwnershipAndPartialFailure(t *testing.T){ _,a:=openTest(t);_,b:=openTest(t);_,c:=openTest(t);ctx:=context.Background(); ai,_:=a.UpdateIdentity(ctx,"a","https://a.example","1");bi,_:=b.UpdateIdentity(ctx,"b","https://b.example","1");ci,_:=c.UpdateIdentity(ctx,"c","https://c.example","1"); sec:=func()(string,string){x,_:=core.NewSecret(32);y,_:=core.NewSecret(32);return x,y};x,y:=sec();_ = a.AddMember(ctx,bi,x,y);x,y=sec();_ = a.AddMember(ctx,ci,x,y);members,_:=a.Members(ctx);local:=Summary{NodeID:ai.NodeID,Collections:1};report,err:=Aggregate(ctx,ai.NodeID,local,members,"all",func(_ context.Context,id string)(Summary,error){if id==ci.NodeID{return Summary{},context.DeadlineExceeded};return Summary{NodeID:id,Collections:2},nil});if err!=nil{t.Fatal(err)};if !report.Partial||len(report.Results)!=3{t.Fatalf("partial=%v results=%d",report.Partial,len(report.Results))};for _,r:=range report.Results{if r.OwnerNode!=r.NodeID{t.Fatalf("owner %s node %s",r.OwnerNode,r.NodeID)}}}
func TestHealthTransitions(t *testing.T){m:=Member{State:core.MemberActive,Compatible:true};if got:=health(m,time.Now());got!=core.HealthOffline{t.Fatalf("health=%s",got)};now:=time.Now();m.LastSeenAt=&now;if got:=health(m,now);got!=core.HealthOnline{t.Fatalf("health=%s",got)}}
