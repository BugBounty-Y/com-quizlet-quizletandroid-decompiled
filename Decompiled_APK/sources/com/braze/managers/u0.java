package com.braze.managers;

import android.app.AlarmManager;
import android.content.Context;
import com.braze.configuration.BrazeConfigurationProvider;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u0 implements h0 {
    public final C1495h A;
    public final com.braze.storage.x B;
    public final com.braze.storage.p C;
    public final com.braze.requests.h D;
    public final com.braze.requests.framework.g E;
    public final com.braze.triggers.managers.f F;
    public final Context a;
    public final BrazeConfigurationProvider b;
    public final e0 c;
    public final i0 d;
    public final d0 e;
    public final boolean f;
    public final String g;
    public final String h;
    public final com.braze.storage.a0 i;
    public final com.braze.storage.h0 j;
    public final com.braze.storage.r k;
    public final com.braze.events.d l;
    public final com.braze.storage.e0 m;
    public final y n;
    public final com.braze.events.a o;
    public final com.braze.dispatch.f p;
    public final r q;
    public final z r;
    public final k0 s;
    public final com.braze.storage.z t;
    public final com.braze.storage.y u;
    public final com.braze.storage.b0 v;
    public final C1500m w;
    public final BrazeGeofenceManager x;
    public final C1498k y;
    public final a0 z;

    public u0(Context applicationContext, com.braze.configuration.e offlineUserStorageProvider, BrazeConfigurationProvider configurationProvider, com.braze.events.e externalEventPublisher, e0 deviceIdProvider, g0 registrationDataProvider, i0 pushDeliveryManager, boolean z, boolean z2, d0 deviceDataProvider, boolean z3) {
        Context context;
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        Intrinsics.checkNotNullParameter(offlineUserStorageProvider, "offlineUserStorageProvider");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        Intrinsics.checkNotNullParameter(externalEventPublisher, "externalEventPublisher");
        Intrinsics.checkNotNullParameter(deviceIdProvider, "deviceIdProvider");
        Intrinsics.checkNotNullParameter(registrationDataProvider, "registrationDataProvider");
        Intrinsics.checkNotNullParameter(pushDeliveryManager, "pushDeliveryManager");
        Intrinsics.checkNotNullParameter(deviceDataProvider, "deviceDataProvider");
        this.a = applicationContext;
        this.b = configurationProvider;
        this.c = deviceIdProvider;
        this.d = pushDeliveryManager;
        this.e = deviceDataProvider;
        this.f = z3;
        String strA = offlineUserStorageProvider.a();
        this.g = strA;
        String str = configurationProvider.getBrazeApiKey().a;
        this.h = str;
        com.braze.storage.a0 a0Var = new com.braze.storage.a0(applicationContext);
        this.i = a0Var;
        com.braze.requests.util.a aVar = new com.braze.requests.util.a(applicationContext);
        com.braze.events.d dVar = new com.braze.events.d(a0Var, true);
        this.l = dVar;
        com.braze.storage.e0 e0Var = new com.braze.storage.e0(applicationContext, str, dVar);
        this.m = e0Var;
        this.n = new y(e0Var, dVar, applicationContext, strA, str);
        new s0(e0Var, dVar, applicationContext);
        com.braze.storage.s sVar = new com.braze.storage.s(new com.braze.storage.g0(applicationContext, strA, str), dVar);
        com.braze.dispatch.f fVar = new com.braze.dispatch.f(applicationContext, dVar, new com.braze.dispatch.a(applicationContext));
        this.p = fVar;
        Object systemService = applicationContext.getSystemService("alarm");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.AlarmManager");
        r rVar = new r(applicationContext, sVar, dVar, externalEventPublisher, (AlarmManager) systemService, configurationProvider.getSessionTimeoutSeconds(), configurationProvider.isSessionStartBasedTimeoutEnabled());
        this.q = rVar;
        z zVar = new z(new com.braze.storage.v(new com.braze.storage.f0(applicationContext, strA, str), dVar));
        this.r = zVar;
        k0 k0Var = new k0(applicationContext, str, strA, dVar, e0Var);
        this.s = k0Var;
        this.t = new com.braze.storage.z(applicationContext, strA, str);
        C1501n c1501n = new C1501n(applicationContext, dVar, e0Var);
        com.braze.storage.y yVar = new com.braze.storage.y(applicationContext, str, strA);
        this.u = yVar;
        com.braze.storage.b0 b0Var = new com.braze.storage.b0(applicationContext, strA, str);
        this.v = b0Var;
        C1500m c1500m = new C1500m(applicationContext, strA, str, rVar, dVar, configurationProvider, e0Var, zVar, c1501n, a0Var, k0Var, pushDeliveryManager, yVar);
        this.w = c1500m;
        BrazeGeofenceManager brazeGeofenceManager = new BrazeGeofenceManager(applicationContext, str, c1500m, configurationProvider, e0Var, dVar);
        this.x = brazeGeofenceManager;
        C1498k c1498k = new C1498k(applicationContext, c1500m, configurationProvider);
        this.y = c1498k;
        a0 a0Var2 = new a0(applicationContext, str, strA, dVar, externalEventPublisher, e0Var, c1500m);
        this.z = a0Var2;
        C1495h c1495h = new C1495h(applicationContext, str, strA, dVar, externalEventPublisher, e0Var, c1500m);
        this.A = c1495h;
        com.braze.storage.x xVar = new com.braze.storage.x(applicationContext, strA, c1500m);
        this.B = xVar;
        com.braze.storage.p pVar = new com.braze.storage.p(applicationContext, strA, str, c1500m, "36.0.0");
        this.C = pVar;
        int i = com.braze.communication.c.a;
        com.braze.requests.u uVar = new com.braze.requests.u(new com.braze.communication.e(new com.braze.communication.b(com.braze.communication.c.a)), dVar, externalEventPublisher, xVar, e0Var, pVar, c1500m, aVar);
        this.D = new com.braze.requests.h(dVar, c1500m);
        com.braze.requests.framework.g gVar = new com.braze.requests.framework.g(new com.braze.dispatch.h(this), uVar, z, z3);
        this.E = gVar;
        com.braze.triggers.managers.f fVar2 = new com.braze.triggers.managers.f(applicationContext, c1500m, dVar, externalEventPublisher, configurationProvider, strA, str, gVar);
        this.F = fVar2;
        if (Intrinsics.b(strA, "")) {
            context = applicationContext;
            com.braze.storage.h0 h0Var = new com.braze.storage.h0(context, registrationDataProvider, a0Var, null, null);
            Intrinsics.checkNotNullParameter(h0Var, "<set-?>");
            this.j = h0Var;
            com.braze.storage.r rVar2 = new com.braze.storage.r(context, null, null);
            Intrinsics.checkNotNullParameter(rVar2, "<set-?>");
            this.k = rVar2;
        } else {
            context = applicationContext;
            com.braze.storage.h0 h0Var2 = new com.braze.storage.h0(context, registrationDataProvider, a0Var, strA, str);
            Intrinsics.checkNotNullParameter(h0Var2, "<set-?>");
            this.j = h0Var2;
            com.braze.storage.r rVar3 = new com.braze.storage.r(context, strA, str);
            Intrinsics.checkNotNullParameter(rVar3, "<set-?>");
            this.k = rVar3;
        }
        synchronized (fVar) {
            try {
                fVar.l = z2;
                fVar.b();
                if (z2) {
                    fVar.f();
                } else {
                    fVar.c();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.braze.storage.h0 h0VarA = a();
        com.braze.storage.r rVar4 = this.k;
        if (rVar4 != null) {
            this.o = new com.braze.events.a(context, c1498k, dVar, c1500m, h0VarA, rVar4, fVar2, fVar2.h, zVar, brazeGeofenceManager, externalEventPublisher, configurationProvider, pVar, b0Var, e0Var, a0Var2, pushDeliveryManager, c1495h);
        } else {
            Intrinsics.m("deviceCache");
            throw null;
        }
    }

    public final com.braze.storage.h0 a() {
        com.braze.storage.h0 h0Var = this.j;
        if (h0Var != null) {
            return h0Var;
        }
        Intrinsics.m("userCache");
        throw null;
    }
}
