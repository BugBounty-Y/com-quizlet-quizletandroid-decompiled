package com.braze.events;

import android.content.Context;
import androidx.lifecycle.C1247h;
import com.braze.Braze;
import com.braze.BrazeInternal;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.events.internal.f0;
import com.braze.events.internal.g0;
import com.braze.events.internal.m;
import com.braze.events.internal.u;
import com.braze.events.internal.w;
import com.braze.events.internal.y;
import com.braze.managers.BrazeGeofenceManager;
import com.braze.managers.C1494g;
import com.braze.managers.C1495h;
import com.braze.managers.C1498k;
import com.braze.managers.C1500m;
import com.braze.managers.a0;
import com.braze.managers.i0;
import com.braze.managers.z;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.outgoing.l;
import com.braze.requests.n;
import com.braze.requests.q;
import com.braze.storage.b0;
import com.braze.storage.e0;
import com.braze.storage.h0;
import com.braze.storage.p;
import com.braze.storage.r;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final AtomicBoolean A;
    public final AtomicBoolean B;
    public final Context a;
    public final C1498k b;
    public final e c;
    public final C1500m d;
    public final h0 e;
    public final r f;
    public final com.braze.triggers.managers.f g;
    public final com.braze.triggers.managers.g h;
    public final z i;
    public final BrazeGeofenceManager j;
    public final e k;
    public final BrazeConfigurationProvider l;
    public final p m;
    public final b0 n;
    public final e0 o;
    public final a0 p;
    public final i0 q;
    public final C1495h r;
    public final AtomicBoolean s;
    public final AtomicBoolean t;
    public com.braze.events.internal.e0 u;
    public final AtomicBoolean v;
    public final AtomicBoolean w;
    public final AtomicBoolean x;
    public final AtomicBoolean y;
    public final AtomicBoolean z;

    public a(Context applicationContext, C1498k locationManager, e internalEventPublisher, C1500m brazeManager, h0 userCache, r deviceCache, com.braze.triggers.managers.f triggerManager, com.braze.triggers.managers.g triggerReEligibilityManager, z eventStorageManager, BrazeGeofenceManager geofenceManager, e externalEventPublisher, BrazeConfigurationProvider configurationProvider, p contentCardsStorageProvider, b0 sdkMetadataCache, e0 serverConfigStorageProvider, a0 featureFlagsManager, i0 pushDeliveryManager, C1495h bannersManager) {
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        Intrinsics.checkNotNullParameter(locationManager, "locationManager");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(userCache, "userCache");
        Intrinsics.checkNotNullParameter(deviceCache, "deviceCache");
        Intrinsics.checkNotNullParameter(triggerManager, "triggerManager");
        Intrinsics.checkNotNullParameter(triggerReEligibilityManager, "triggerReEligibilityManager");
        Intrinsics.checkNotNullParameter(eventStorageManager, "eventStorageManager");
        Intrinsics.checkNotNullParameter(geofenceManager, "geofenceManager");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        Intrinsics.checkNotNullParameter(contentCardsStorageProvider, "contentCardsStorageProvider");
        Intrinsics.checkNotNullParameter(sdkMetadataCache, "sdkMetadataCache");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(featureFlagsManager, "featureFlagsManager");
        Intrinsics.checkNotNullParameter(pushDeliveryManager, "pushDeliveryManager");
        Intrinsics.checkNotNullParameter(bannersManager, "bannersManager");
        this.a = applicationContext;
        this.b = locationManager;
        this.c = internalEventPublisher;
        this.d = brazeManager;
        this.e = userCache;
        this.f = deviceCache;
        this.g = triggerManager;
        this.h = triggerReEligibilityManager;
        this.i = eventStorageManager;
        this.j = geofenceManager;
        this.k = externalEventPublisher;
        this.l = configurationProvider;
        this.m = contentCardsStorageProvider;
        this.n = sdkMetadataCache;
        this.o = serverConfigStorageProvider;
        this.p = featureFlagsManager;
        this.q = pushDeliveryManager;
        this.r = bannersManager;
        this.s = new AtomicBoolean(false);
        this.t = new AtomicBoolean(false);
        this.v = new AtomicBoolean(false);
        this.w = new AtomicBoolean(false);
        this.x = new AtomicBoolean(false);
        this.y = new AtomicBoolean(false);
        this.z = new AtomicBoolean(false);
        this.A = new AtomicBoolean(false);
        this.B = new AtomicBoolean(false);
    }

    public static final String J() {
        return "Requesting Banners refresh on session created event due to configuration.";
    }

    public static final String K() {
        return "Banners already initialized. Not retrieving.";
    }

    public static final String M() {
        return "Requesting Content Card refresh on session created event due to configuration.";
    }

    public static final String N() {
        return "Content Cards already initialized. Not retrieving.";
    }

    public static final String P() {
        return "Starting DUST subscription due to configuration.";
    }

    public static final String Q() {
        return "DUST initial subscription already started. Not starting again.";
    }

    public static final String S() {
        return "Requesting Feature Flags refresh on session created event due to configuration.";
    }

    public static final String T() {
        return "Feature Flags already initialized. Not retrieving.";
    }

    public static final String V() {
        return "Requesting Push Max request on session created event due to configuration.";
    }

    public static final String W() {
        return "Push Max already requested for this session. Not requesting again.";
    }

    public static final String Y() {
        return "Doing Debugger Handshake.";
    }

    public static final String Z() {
        return "Debugger Initialization already attempted. Not doing Debugger initialization again.";
    }

    public static final void a(a aVar, com.braze.events.internal.a aVar2) {
        Intrinsics.checkNotNullParameter(aVar2, "<destruct>");
        ((d) aVar.k).b(aVar.r.a(aVar2.a), BannersUpdatedEvent.class);
    }

    public static final String b() {
        return "Failed to request a content card refresh.";
    }

    public static final String b0() {
        return "Performing push delivery event flush";
    }

    public static final String c() {
        return "Requesting Braze Geofence refresh on session created event due to configuration.";
    }

    public static final String d() {
        return "Not automatically requesting Braze Geofence refresh on session created event due to configuration.";
    }

    public static final String d0() {
        return "Requesting feed refresh in next sync";
    }

    public static final String e() {
        return "Session created event for new session received.";
    }

    public static final String e0() {
        return "Requesting trigger refresh in next sync";
    }

    public static final String f() {
        return "Session start event for new session received.";
    }

    public static final String g() {
        return "Not automatically requesting Content Card refresh on session created event due to server configuration.";
    }

    public static final String h() {
        return "Not automatically requesting Feature Flags refresh on session created event due to server configuration.";
    }

    public static final String i() {
        return "Not automatically requesting Push Max on session created event due to server configuration.";
    }

    public static final String j() {
        return "Not automatically starting DUST subscription on session created event due to server configuration.";
    }

    public static final String k() {
        return "Not automatically requesting Banners refresh on session created event due to server configuration.";
    }

    public static final String l() {
        return "Not automatically starting SDK Debugger on session created event due to server configuration.";
    }

    public static final String m() {
        return "Failed to log the storage exception.";
    }

    public static final String n() {
        return "Requesting trigger update due to trigger-eligible push click event";
    }

    public static final String u() {
        return "Failed to log error.";
    }

    public final IEventSubscriber A() {
        return new f(this, 7);
    }

    public final IEventSubscriber B() {
        return new f(this, 15);
    }

    public final IEventSubscriber C() {
        return new f(this, 2);
    }

    public final IEventSubscriber D() {
        return new f(this, 11);
    }

    public final IEventSubscriber E() {
        return new f(this, 6);
    }

    public final IEventSubscriber F() {
        return new f(this, 4);
    }

    public final IEventSubscriber G() {
        return new f(this, 17);
    }

    public final IEventSubscriber H() {
        return new f(this, 16);
    }

    public final void I() {
        if (!this.A.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(12), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(11), 7, (Object) null);
        C1495h c1495h = this.r;
        C1494g c1494g = C1495h.k;
        c1495h.a(false);
    }

    public final void L() {
        if (!this.w.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(28), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(27), 7, (Object) null);
        C1500m c1500m = this.d;
        p pVar = this.m;
        c1500m.a(pVar.c, pVar.d, 0);
    }

    public final void O() {
        if (!this.z.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(14), 7, (Object) null);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(13), 7, (Object) null);
            this.d.z();
        }
    }

    public final void R() {
        if (!this.x.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(10), 7, (Object) null);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(9), 7, (Object) null);
            this.p.d.w();
        }
    }

    public final void U() {
        if (!this.y.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(22), 7, (Object) null);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(21), 7, (Object) null);
            this.d.C();
        }
    }

    public final void X() {
        if (!this.B.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(16), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(15), 7, (Object) null);
        ((d) this.c).b(new u(), u.class);
    }

    public final void a0() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(1), 7, (Object) null);
        this.d.a(0L);
    }

    public final void c0() {
        com.braze.models.outgoing.j jVar = new com.braze.models.outgoing.j();
        if (this.d.t.get()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(25), 7, (Object) null);
            jVar.b = Boolean.TRUE;
            this.d.a(false);
        }
        if (this.d.s.get()) {
            this.s.set(true);
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(26), 7, (Object) null);
            jVar.c = Boolean.TRUE;
            this.d.b(false);
        }
        Boolean bool = jVar.c;
        Boolean bool2 = Boolean.TRUE;
        if (Intrinsics.b(bool, bool2) || Intrinsics.b(jVar.b, bool2)) {
            this.d.a(jVar);
        }
    }

    public final IEventSubscriber o() {
        return new f(this, 10);
    }

    public final IEventSubscriber p() {
        return new f(this, 13);
    }

    public final IEventSubscriber q() {
        return new f(this, 14);
    }

    public final IEventSubscriber r() {
        return new f(this, 12);
    }

    public final IEventSubscriber s() {
        return new f(this, 0);
    }

    public final IEventSubscriber t() {
        return new f(this, 1);
    }

    public final IEventSubscriber v() {
        return new f(this, 18);
    }

    public final IEventSubscriber w() {
        return new f(this, 5);
    }

    public final IEventSubscriber x() {
        return new f(this, 8);
    }

    public final IEventSubscriber y() {
        return new f(this, 3);
    }

    public final IEventSubscriber z() {
        return new f(this, 9);
    }

    public static final void a(a aVar, com.braze.events.internal.f fVar) {
        com.braze.events.internal.e0 e0Var;
        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
        n nVar = fVar.a;
        com.braze.models.outgoing.h hVar = ((com.braze.requests.b) nVar).h;
        if (hVar != null) {
            aVar.f.a((Object) hVar, false);
        }
        if (nVar instanceof com.braze.requests.f) {
            com.braze.requests.f fVar2 = (com.braze.requests.f) nVar;
            if (fVar2.j.b()) {
                if (aVar.s.compareAndSet(true, false)) {
                    aVar.g.a((com.braze.triggers.events.i) new com.braze.triggers.events.e());
                }
                if (aVar.t.compareAndSet(true, false) && (e0Var = aVar.u) != null) {
                    aVar.g.a((com.braze.triggers.events.i) new com.braze.triggers.events.g(e0Var.a, e0Var.b));
                    aVar.u = null;
                }
                aVar.d.b(true);
            }
            l lVar = fVar2.l;
            if (lVar != null) {
                aVar.e.a((Object) lVar, false);
                if (lVar.a.has("push_token")) {
                    aVar.e.j();
                    aVar.f.e();
                }
            }
            com.braze.models.b bVar = fVar2.m;
            if (bVar != null) {
                for (com.braze.models.i iVar : bVar.a) {
                    e eVar = aVar.c;
                    List events = A.b(iVar);
                    Intrinsics.checkNotNullParameter(events, "events");
                    ((d) eVar).b(new com.braze.events.internal.dispatchmanager.c(com.braze.events.internal.dispatchmanager.b.b, events, null, null, 12), com.braze.events.internal.dispatchmanager.c.class);
                }
            }
            if (fVar2.j.d != null) {
                aVar.o.M();
            }
        }
        if (nVar instanceof q) {
            aVar.q.b(((q) nVar).j);
        }
    }

    public static final void a(a aVar, com.braze.events.internal.g gVar) {
        Intrinsics.checkNotNullParameter(gVar, "<destruct>");
        n nVar = gVar.a;
        com.braze.models.outgoing.h hVar = ((com.braze.requests.b) nVar).h;
        if (hVar != null) {
            aVar.f.a((Object) hVar, true);
        }
        if (nVar instanceof com.braze.requests.f) {
            com.braze.requests.f fVar = (com.braze.requests.f) nVar;
            l lVar = fVar.l;
            if (lVar != null) {
                aVar.e.a((Object) lVar, true);
            }
            com.braze.models.b bVar = fVar.m;
            if (bVar != null) {
                aVar.i.a(bVar.a);
            }
            if (fVar.j.b()) {
                aVar.d.b(false);
            }
            EnumSet enumSet = fVar.n;
            if (enumSet != null) {
                aVar.n.a(enumSet);
            }
            if (fVar.j.d != null) {
                aVar.o.M();
            }
        }
        if (nVar instanceof q) {
            aVar.q.a(((q) nVar).j);
        }
    }

    public static final void a(a aVar, com.braze.events.internal.i iVar) {
        Intrinsics.checkNotNullParameter(iVar, "<destruct>");
        ((d) aVar.k).b(aVar.p.a(iVar.a), FeatureFlagsUpdatedEvent.class);
    }

    public static final void a(a aVar, com.braze.events.internal.l lVar) {
        Intrinsics.checkNotNullParameter(lVar, "<destruct>");
        aVar.j.registerGeofences(lVar.a);
    }

    public static final void a(a aVar, m mVar) {
        Intrinsics.checkNotNullParameter(mVar, "<destruct>");
        com.braze.triggers.events.b bVar = mVar.a;
        com.braze.triggers.actions.h hVar = mVar.b;
        IInAppMessage iInAppMessage = mVar.c;
        String str = mVar.d;
        synchronized (aVar.h) {
            try {
                if (aVar.h.a((com.braze.triggers.actions.g) hVar)) {
                    ((d) aVar.k).b(new InAppMessageEvent(bVar, hVar, iInAppMessage, str), InAppMessageEvent.class);
                    aVar.h.a(hVar, DateTimeUtils.nowInSeconds());
                    aVar.g.b(DateTimeUtils.nowInSeconds());
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new g(hVar, 0), 7, (Object) null);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final void a(a aVar, w wVar) {
        Intrinsics.checkNotNullParameter(wVar, "<destruct>");
        com.braze.models.response.m mVar = wVar.a;
        aVar.j.configureFromServerConfig(mVar);
        if (aVar.v.get()) {
            if (mVar.j) {
                aVar.L();
            }
            if (mVar.m) {
                aVar.R();
            }
            if (mVar.o) {
                aVar.U();
            }
            if (mVar.t) {
                aVar.O();
            }
            if (mVar.F) {
                aVar.I();
            }
            if (mVar.y) {
                aVar.X();
            }
        }
    }

    public static final void a(a aVar, f0 f0Var) {
        Intrinsics.checkNotNullParameter(f0Var, "<destruct>");
        aVar.g.a((com.braze.triggers.events.i) f0Var.a);
    }

    public static final void a(a aVar, g0 g0Var) {
        Intrinsics.checkNotNullParameter(g0Var, "<destruct>");
        aVar.g.a(g0Var.a, g0Var.b);
    }

    public static final void a(a aVar, com.braze.events.internal.h0 h0Var) {
        com.braze.events.internal.e0 e0Var;
        Intrinsics.checkNotNullParameter(h0Var, "<destruct>");
        aVar.g.a(h0Var.a);
        if (aVar.s.compareAndSet(true, false)) {
            aVar.g.a((com.braze.triggers.events.i) new com.braze.triggers.events.e());
        }
        if (!aVar.t.compareAndSet(true, false) || (e0Var = aVar.u) == null) {
            return;
        }
        aVar.g.a((com.braze.triggers.events.i) new com.braze.triggers.events.g(e0Var.a, e0Var.b));
        aVar.u = null;
    }

    public static final void a(a aVar, com.braze.events.internal.d event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (!event.a.j || event.b.j) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(24), 7, (Object) null);
        aVar.m.a();
    }

    public static final void a(a aVar, y it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(18), 7, (Object) null);
        aVar.w.set(false);
        aVar.x.set(false);
        aVar.y.set(false);
        aVar.z.set(false);
        aVar.B.set(false);
        aVar.b.g();
        com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(it2.a.a);
        if (iVarA != null) {
            ((com.braze.models.outgoing.event.b) iVarA).a(it2.a.a);
        }
        if (iVarA != null) {
            aVar.d.a(iVarA);
        }
        aVar.d.b(true);
        aVar.d.a(true);
        aVar.e.j();
        aVar.f.e();
        aVar.a0();
        if (aVar.l.isAutomaticGeofenceRequestsEnabled()) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(19), 7, (Object) null);
            BrazeInternal.requestGeofenceRefresh(aVar.a, false);
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(20), 7, (Object) null);
        }
        aVar.p.g();
        aVar.r.j();
        aVar.c0();
    }

    public static final void a(a aVar, com.braze.events.internal.a0 it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(2), 7, (Object) null);
        aVar.v.set(true);
        if (aVar.o.D()) {
            aVar.L();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(3), 7, (Object) null);
        }
        if (aVar.o.G()) {
            aVar.R();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(4), 7, (Object) null);
        }
        if (aVar.o.K()) {
            aVar.U();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(5), 7, (Object) null);
        }
        if (aVar.o.E()) {
            aVar.O();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(6), 7, (Object) null);
        }
        if (aVar.o.d()) {
            aVar.I();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(7), 7, (Object) null);
        }
        if (aVar.o.L()) {
            aVar.X();
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) aVar, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(8), 7, (Object) null);
        }
    }

    public static final void a(a aVar, com.braze.events.internal.n it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        aVar.d.b(true);
        aVar.c0();
    }

    public static final void a(a aVar, com.braze.events.internal.z message) {
        Intrinsics.checkNotNullParameter(message, "message");
        aVar.getClass();
        com.braze.models.n nVar = message.a;
        com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(nVar.c());
        if (iVarA != null) {
            ((com.braze.models.outgoing.event.b) iVarA).a(nVar.a);
            aVar.d.a(iVarA);
        }
        Braze.Companion.getInstance(aVar.a).requestImmediateDataFlush();
        aVar.a0();
    }

    public static final void a(a aVar, com.braze.events.internal.e0 message) {
        Intrinsics.checkNotNullParameter(message, "message");
        aVar.t.set(true);
        aVar.u = message;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) aVar, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.configuration.h(23), 6, (Object) null);
        C1500m c1500m = aVar.d;
        com.braze.models.outgoing.j jVar = new com.braze.models.outgoing.j();
        jVar.c = Boolean.TRUE;
        c1500m.a(jVar);
    }

    public static final String a(com.braze.triggers.actions.a aVar) {
        return "Could not publish in-app message with trigger action id: " + ((com.braze.triggers.actions.g) aVar).a;
    }

    public static final void a(a aVar, com.braze.exceptions.b throwable) {
        Intrinsics.checkNotNullParameter(throwable, "storageException");
        try {
            C1500m c1500m = aVar.d;
            Intrinsics.checkNotNullParameter(throwable, "throwable");
            c1500m.a((Throwable) throwable, false);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) aVar, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new h(0), 4, (Object) null);
        }
    }

    public static final void a(a aVar, com.braze.events.internal.e it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        try {
            C1500m c1500m = aVar.d;
            p pVar = aVar.m;
            c1500m.a(pVar.c, pVar.d, 0);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) aVar, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.configuration.h(17), 4, (Object) null);
        }
    }

    public static final String a() {
        return "Content cards have moved to disabled. Clearing content card data.";
    }

    public final void a(d eventMessenger) {
        Intrinsics.checkNotNullParameter(eventMessenger, "eventMessenger");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1247h(eventMessenger, 13), 7, (Object) null);
        eventMessenger.c(com.braze.events.internal.f.class, r());
        eventMessenger.c(com.braze.events.internal.g.class, s());
        eventMessenger.c(y.class, A());
        eventMessenger.c(com.braze.events.internal.a0.class, C());
        eventMessenger.c(com.braze.events.internal.z.class, B());
        eventMessenger.c(com.braze.events.internal.e0.class, E());
        eventMessenger.c(w.class, z());
        eventMessenger.c(Throwable.class, t());
        eventMessenger.c(com.braze.exceptions.b.class, D());
        eventMessenger.c(com.braze.events.internal.h0.class, H());
        eventMessenger.c(com.braze.events.internal.n.class, y());
        eventMessenger.c(com.braze.events.internal.l.class, w());
        eventMessenger.c(com.braze.events.internal.i.class, v());
        eventMessenger.c(com.braze.events.internal.a.class, o());
        eventMessenger.c(f0.class, F());
        eventMessenger.c(m.class, x());
        eventMessenger.c(g0.class, G());
        eventMessenger.c(com.braze.events.internal.e.class, q());
        eventMessenger.c(com.braze.events.internal.d.class, p());
    }

    public static final String a(e eVar) {
        return "Subscribing to events with " + eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.braze.events.a r8, java.util.concurrent.Semaphore r9, java.lang.Throwable r10) {
        /*
            if (r10 == 0) goto L2f
            com.braze.managers.m r0 = r8.d     // Catch: java.lang.Throwable -> Le java.lang.Exception -> L11
            java.lang.String r1 = "throwable"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r1)     // Catch: java.lang.Throwable -> Le java.lang.Exception -> L11
            r1 = 1
            r0.a(r10, r1)     // Catch: java.lang.Throwable -> Le java.lang.Exception -> L11
            goto L2f
        Le:
            r0 = move-exception
            r8 = r0
            goto L29
        L11:
            r0 = move-exception
            r10 = r0
            r3 = r10
            com.braze.support.BrazeLogger r0 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Throwable -> Le
            com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.E     // Catch: java.lang.Throwable -> Le
            com.braze.configuration.h r5 = new com.braze.configuration.h     // Catch: java.lang.Throwable -> Le
            r10 = 29
            r5.<init>(r10)     // Catch: java.lang.Throwable -> Le
            r6 = 4
            r7 = 0
            r4 = 0
            r1 = r8
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> Le
            if (r9 == 0) goto L34
            goto L31
        L29:
            if (r9 == 0) goto L2e
            r9.release()
        L2e:
            throw r8
        L2f:
            if (r9 == 0) goto L34
        L31:
            r9.release()
        L34:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.events.a.a(com.braze.events.a, java.util.concurrent.Semaphore, java.lang.Throwable):void");
    }
}
