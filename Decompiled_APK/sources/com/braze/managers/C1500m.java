package com.braze.managers;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.SystemClock;
import com.braze.AbstractC1484j;
import com.braze.BrazeFlushPushDeliveryReceiver;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.events.IEventSubscriber;
import com.braze.models.IBrazeLocation;
import com.braze.requests.C1512a;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.IntentUtils;
import com.braze.support.JsonUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: com.braze.managers.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1500m implements c0 {
    public static final String[] v = {"android.os.deadsystemexception"};
    public final Context a;
    public final String b;
    public final r c;
    public final com.braze.events.d d;
    public final BrazeConfigurationProvider e;
    public final com.braze.storage.e0 f;
    public final z g;
    public final C1501n h;
    public final com.braze.storage.a0 i;
    public final k0 j;
    public final i0 k;
    public final com.braze.storage.y l;
    public final AtomicInteger m;
    public final AtomicInteger n;
    public final ReentrantLock o;
    public InterfaceC5025j0 p;
    public final com.braze.storage.t q;
    public volatile String r;
    public final AtomicBoolean s;
    public final AtomicBoolean t;
    public Class u;

    public C1500m(Context context, String str, String apiKey, r sessionManager, com.braze.events.d internalEventPublisher, BrazeConfigurationProvider configurationProvider, com.braze.storage.e0 serverConfigStorageProvider, z eventStorageManager, C1501n messagingSessionManager, com.braze.storage.a0 sdkEnablementProvider, k0 pushMaxManager, i0 pushDeliveryManager, com.braze.storage.y pushIdentifierStorageProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(sessionManager, "sessionManager");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(eventStorageManager, "eventStorageManager");
        Intrinsics.checkNotNullParameter(messagingSessionManager, "messagingSessionManager");
        Intrinsics.checkNotNullParameter(sdkEnablementProvider, "sdkEnablementProvider");
        Intrinsics.checkNotNullParameter(pushMaxManager, "pushMaxManager");
        Intrinsics.checkNotNullParameter(pushDeliveryManager, "pushDeliveryManager");
        Intrinsics.checkNotNullParameter(pushIdentifierStorageProvider, "pushIdentifierStorageProvider");
        this.a = context;
        this.b = str;
        this.c = sessionManager;
        this.d = internalEventPublisher;
        this.e = configurationProvider;
        this.f = serverConfigStorageProvider;
        this.g = eventStorageManager;
        this.h = messagingSessionManager;
        this.i = sdkEnablementProvider;
        this.j = pushMaxManager;
        this.k = pushDeliveryManager;
        this.l = pushIdentifierStorageProvider;
        this.m = new AtomicInteger(0);
        this.n = new AtomicInteger(0);
        this.o = new ReentrantLock();
        this.p = kotlinx.coroutines.E.d();
        this.q = new com.braze.storage.t(context, str, apiKey);
        this.r = "";
        this.s = new AtomicBoolean(false);
        this.t = new AtomicBoolean(false);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new K(4), 6, (Object) null);
        final int i = 0;
        internalEventPublisher.c(com.braze.events.internal.s.class, new IEventSubscriber(this) { // from class: com.braze.managers.L
            public final /* synthetic */ C1500m b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        if (obj != null) {
                            throw new ClassCastException();
                        }
                        C1500m.a(this.b, (com.braze.events.internal.s) null);
                        return;
                    case 1:
                        C1500m.a(this.b, (com.braze.events.internal.u) obj);
                        return;
                    default:
                        C1500m.a(this.b, (com.braze.events.internal.v) obj);
                        return;
                }
            }
        });
        final int i2 = 1;
        internalEventPublisher.c(com.braze.events.internal.u.class, new IEventSubscriber(this) { // from class: com.braze.managers.L
            public final /* synthetic */ C1500m b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        if (obj != null) {
                            throw new ClassCastException();
                        }
                        C1500m.a(this.b, (com.braze.events.internal.s) null);
                        return;
                    case 1:
                        C1500m.a(this.b, (com.braze.events.internal.u) obj);
                        return;
                    default:
                        C1500m.a(this.b, (com.braze.events.internal.v) obj);
                        return;
                }
            }
        });
        final int i3 = 2;
        internalEventPublisher.c(com.braze.events.internal.v.class, new IEventSubscriber(this) { // from class: com.braze.managers.L
            public final /* synthetic */ C1500m b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i3) {
                    case 0:
                        if (obj != null) {
                            throw new ClassCastException();
                        }
                        C1500m.a(this.b, (com.braze.events.internal.s) null);
                        return;
                    case 1:
                        C1500m.a(this.b, (com.braze.events.internal.u) obj);
                        return;
                    default:
                        C1500m.a(this.b, (com.braze.events.internal.v) obj);
                        return;
                }
            }
        });
    }

    public static final String A() {
        return "Requesting DUST mite";
    }

    public static final String B() {
        return "Posting geofence request for location.";
    }

    public static final String D() {
        return "Sending Push Max data";
    }

    public static final String E() {
        return "Posting SDK Debugger Logs request.";
    }

    public static final String a() {
        return "BrazeManager init called";
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Logging push delivery event for campaign id: ", str);
    }

    public static final String c(C1500m c1500m) {
        return "Completed the openSession call. Starting or continuing session " + c1500m.c.g();
    }

    public static final String d(Activity activity) {
        return "Opened session with activity: " + activity.getLocalClassName();
    }

    public static final String e(com.braze.models.i iVar) {
        return "Not adding session id to event: " + JsonUtils.getPrettyPrintedString(((com.braze.models.outgoing.event.b) iVar).forJsonPut());
    }

    public static final String g() {
        return "SDK is disabled. Not force closing session.";
    }

    public static final String h() {
        return "BrazeManager got SdkDebuggerInitializationRequestedEvent";
    }

    public static final String i() {
        return "Braze SDK Debugger logs being sent";
    }

    public static final String j() {
        return "Failed to log error.";
    }

    public static final String k() {
        return "Publishing an internal push body clicked event for any awaiting triggers.";
    }

    public static final String l() {
        return "Adding push click to dispatcher pending list";
    }

    public static final String m() {
        return "Session in background, data syncing event on delay";
    }

    public static final String n() {
        return "Logging push max campaign";
    }

    public static final String p() {
        return "SDK is disabled. Not opening session.";
    }

    public static final String q() {
        return "Failed to get local class name for activity when opening session";
    }

    public static final String r() {
        return "SDK is disabled. Not opening session.";
    }

    public static final String s() {
        return "Flushing Push Delivery Events now";
    }

    public static final String t() {
        return "Attempted to flush Push Delivery events, but no events are available";
    }

    public static final String v() {
        return "Posting banners refresh request.";
    }

    public static final String x() {
        return "Posting feature flags refresh request.";
    }

    public static final String y() {
        return "Disallowing Content Cards sync due to Content Cards not being enabled.";
    }

    public final void C() {
        long j;
        List list;
        if (this.f.K()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(15), 7, (Object) null);
            com.braze.storage.e0 e0Var = this.f;
            String baseUrlForRequests = this.e.getBaseUrlForRequests();
            String str = this.b;
            k0 k0Var = this.j;
            long j2 = k0Var.c.getLong("lastUpdateTime", -1L) - k0Var.a.u();
            SharedPreferences pushMaxPrefs = k0Var.b;
            Intrinsics.checkNotNullExpressionValue(pushMaxPrefs, "pushMaxPrefs");
            ArrayList arrayList = new ArrayList();
            Map<String, ?> all = pushMaxPrefs.getAll();
            Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
            Iterator<Map.Entry<String, ?>> it2 = all.entrySet().iterator();
            while (true) {
                j = 0;
                if (!it2.hasNext()) {
                    break;
                }
                String key = it2.next().getKey();
                Intrinsics.d(key);
                arrayList.add(new j0(key, pushMaxPrefs.getLong(key, 0L)));
            }
            List listW0 = CollectionsKt.w0(arrayList);
            ArrayList arrayList2 = new ArrayList();
            for (Object obj : listW0) {
                long j3 = j;
                if (((j0) obj).b > j2) {
                    arrayList2.add(obj);
                }
                j = j3;
            }
            long j4 = j;
            List listW02 = CollectionsKt.w0(arrayList2);
            ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(listW02, 10));
            Iterator it3 = listW02.iterator();
            while (it3.hasNext()) {
                arrayList3.add(((j0) it3.next()).a);
            }
            long j5 = this.j.c.getLong("lastUpdateTime", -1L);
            com.braze.storage.y yVar = this.l;
            long jV = this.f.v();
            if (jV <= j4) {
                list = kotlin.collections.K.a;
            } else {
                long jNowInSeconds = DateTimeUtils.nowInSeconds() - jV;
                ArrayList arrayList4 = new ArrayList();
                Map<String, ?> all2 = yVar.a.getAll();
                Intrinsics.checkNotNullExpressionValue(all2, "getAll(...)");
                for (Map.Entry<String, ?> entry : all2.entrySet()) {
                    Long l = (Long) entry.getValue();
                    if (l != null && l.longValue() >= jNowInSeconds) {
                        String key2 = entry.getKey();
                        Intrinsics.checkNotNullExpressionValue(key2, "<get-key>(...)");
                        arrayList4.add(key2);
                    }
                }
                list = arrayList4;
            }
            a(new com.braze.requests.r(e0Var, baseUrlForRequests, str, arrayList3, j5, list));
        }
    }

    public final void f() {
        if (this.i.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(14), 6, (Object) null);
        } else {
            this.u = null;
            this.c.k();
        }
    }

    public final void o() {
        com.braze.models.l lVar;
        if (this.i.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(7), 6, (Object) null);
            return;
        }
        r rVar = this.c;
        ReentrantLock reentrantLock = rVar.h;
        reentrantLock.lock();
        try {
            if (rVar.f() && (lVar = rVar.l) != null) {
                rVar.b.a(lVar);
            }
            rVar.k.j(null);
            rVar.a();
            rVar.c.b(com.braze.events.internal.a0.a, com.braze.events.internal.a0.class);
            Unit unit = Unit.a;
            reentrantLock.unlock();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new M(this, 0), 6, (Object) null);
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final void w() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(16), 7, (Object) null);
        a(new com.braze.requests.i(this.f, this.e.getBaseUrlForRequests(), this.b));
    }

    public final void z() {
        if (this.f.E()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new K(13), 6, (Object) null);
            a(new com.braze.requests.g(this.f, this.e.getBaseUrlForRequests(), this.b));
        }
    }

    public static final void a(C1500m c1500m, com.braze.events.internal.s it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        throw null;
    }

    public static final String d(com.braze.models.i iVar) {
        return "Not processing event after validation failed: " + iVar;
    }

    public static final String g(com.braze.models.i iVar) {
        return "Attempting to log event: " + JsonUtils.getPrettyPrintedString(((com.braze.models.outgoing.event.b) iVar).forJsonPut());
    }

    public final void b(boolean z) {
        this.s.set(z);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(this, 1), 6, (Object) null);
    }

    public final void c(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.i.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(5), 6, (Object) null);
            return;
        }
        o();
        this.u = activity.getClass();
        this.h.b();
        try {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.N(6, activity), 6, (Object) null);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new K(6), 4, (Object) null);
        }
    }

    public static final void a(C1500m c1500m, com.braze.events.internal.u it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c1500m, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new K(8), 6, (Object) null);
        c1500m.d();
    }

    public final void d() {
        if (this.f.L()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new K(11), 6, (Object) null);
            a(new com.braze.requests.v(this.f, this.e.getBaseUrlForRequests(), this.b));
        }
    }

    public static final String b(C1500m c1500m) {
        return "Updated shouldRequestTriggersInNextRequest to: " + c1500m.s;
    }

    public static final String e() {
        return "Requesting SDK Debugger Handshake";
    }

    public static final void a(C1500m c1500m, com.braze.events.internal.v it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c1500m, BrazeLogger.Priority.D, (Throwable) null, true, (Function0) new K(9), 2, (Object) null);
        c1500m.b(it2.a);
    }

    public static final String b(Activity activity) {
        return "Closed session with activity: " + activity.getLocalClassName();
    }

    public static final String b(com.braze.models.i iVar) {
        return "BrazeManager logEvent called for: " + JsonUtils.getPrettyPrintedString(((com.braze.models.outgoing.event.b) iVar).forJsonPut());
    }

    public static final String f(com.braze.models.i iVar) {
        return "Not adding user id to event: " + JsonUtils.getPrettyPrintedString(((com.braze.models.outgoing.event.b) iVar).forJsonPut());
    }

    public final void a(boolean z) {
        this.t.set(z);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(this, 2), 6, (Object) null);
    }

    public static final String b() {
        return "SDK is disabled. Not adding request to dispatch.";
    }

    public static final String a(C1500m c1500m) {
        return "Updated shouldRequestFeedInNextRequest to: " + c1500m.t;
    }

    public static final String c() {
        return "SDK is disabled. Not closing session.";
    }

    public final void b(ArrayList arrayList) {
        if (arrayList.isEmpty()) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.D, (Throwable) null, true, (Function0) new K(12), 2, (Object) null);
        a(new com.braze.requests.w(this.f, this.e.getBaseUrlForRequests(), this.b, arrayList));
    }

    public static final String c(com.braze.models.i iVar) {
        return "SDK is disabled. Not logging event: " + iVar;
    }

    public final void a(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (this.i.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(3), 6, (Object) null);
        } else if (this.u == null || activity.getClass().equals(this.u)) {
            this.h.e();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.N(5, activity), 6, (Object) null);
            this.c.n();
        }
    }

    public final void c(String campaignId) {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(10), 7, (Object) null);
        this.j.a(campaignId);
    }

    public static final String b(Throwable th) {
        return "Not logging duplicate error: " + th;
    }

    public static final String b(long j) {
        return androidx.compose.animation.d0.o(j, "Scheduling Push Delivery Events Flush in ", " ms");
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0065  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(com.braze.models.i r17) {
        /*
            Method dump skipped, instructions count: 457
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.managers.C1500m.a(com.braze.models.i):boolean");
    }

    public final void a(com.braze.models.outgoing.j respondWithBuilder) {
        Intrinsics.checkNotNullParameter(respondWithBuilder, "respondWithBuilder");
        Pair pairA = this.f.a();
        if (pairA != null) {
            com.braze.models.outgoing.i outboundConfigParams = new com.braze.models.outgoing.i(((Number) pairA.a).longValue(), ((Boolean) pairA.b).booleanValue());
            Intrinsics.checkNotNullParameter(outboundConfigParams, "outboundConfigParams");
            respondWithBuilder.d = outboundConfigParams;
        }
        if (this.s.get()) {
            respondWithBuilder.c = Boolean.TRUE;
        }
        respondWithBuilder.a = this.b;
        a(new com.braze.requests.f(this.f, this.e.getBaseUrlForRequests(), new com.braze.models.outgoing.k(respondWithBuilder.a, respondWithBuilder.b, respondWithBuilder.c, respondWithBuilder.d)));
        this.s.set(false);
    }

    public final void a(IBrazeLocation location) {
        Intrinsics.checkNotNullParameter(location, "location");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(28), 7, (Object) null);
        a(new com.braze.requests.j(this.f, this.e.getBaseUrlForRequests(), location));
    }

    public final void a(ArrayList ids) {
        Intrinsics.checkNotNullParameter(ids, "ids");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(18), 7, (Object) null);
        a(new C1512a(ids, this.f, this.e.getBaseUrlForRequests(), this.b));
    }

    public final void a(com.braze.requests.b request) {
        Intrinsics.checkNotNullParameter(request, "request");
        if (this.i.a.getBoolean("appboy_sdk_disabled", false)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(1), 6, (Object) null);
            return;
        }
        request.b = this.b;
        com.braze.events.d dVar = this.d;
        Intrinsics.checkNotNullParameter(request, "request");
        dVar.b(new com.braze.events.internal.dispatchmanager.c(com.braze.events.internal.dispatchmanager.b.d, null, null, request, 6), com.braze.events.internal.dispatchmanager.c.class);
    }

    public final void a(long j, long j2, int i) {
        if (!this.f.D()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new K(2), 6, (Object) null);
        } else {
            a(new com.braze.requests.e(this.f, this.e.getBaseUrlForRequests(), j, j2, this.b, i));
        }
    }

    public final boolean a(Throwable th) {
        ReentrantLock reentrantLock = this.o;
        reentrantLock.lock();
        try {
            this.m.getAndIncrement();
            if (Intrinsics.b(this.r, th.getMessage()) && this.n.get() > 3 && this.m.get() < 25) {
                reentrantLock.unlock();
                return true;
            }
            if (Intrinsics.b(this.r, th.getMessage())) {
                this.n.getAndIncrement();
            } else {
                this.n.set(0);
            }
            if (this.m.get() >= 25) {
                this.m.set(0);
            }
            this.r = th.getMessage();
            return false;
        } finally {
            reentrantLock.unlock();
        }
    }

    public final void a(Throwable throwable, boolean z) {
        com.braze.models.i iVarA;
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        try {
            if (a(throwable)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.B(1, throwable), 6, (Object) null);
                return;
            }
            String string = throwable.toString();
            String str = v[0];
            Locale US = Locale.US;
            Intrinsics.checkNotNullExpressionValue(US, "US");
            String lowerCase = string.toLowerCase(US);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            if (StringsKt.G(lowerCase, str, false) || (iVarA = com.braze.models.outgoing.event.b.g.a(throwable, this.c.g(), z)) == null) {
                return;
            }
            a(iVarA);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new K(17), 4, (Object) null);
        }
    }

    public final void a(long j) {
        Object systemService = this.a.getSystemService("alarm");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.AlarmManager");
        AlarmManager alarmManager = (AlarmManager) systemService;
        Intent intent = new Intent(this.a, (Class<?>) BrazeFlushPushDeliveryReceiver.class);
        intent.setAction("com.braze.FLUSH_PUSH_DELIVERY");
        PendingIntent broadcast = PendingIntent.getBroadcast(this.a, 0, intent, IntentUtils.getImmutablePendingIntentFlags() | 134217728);
        if (j <= 0) {
            alarmManager.cancel(broadcast);
            i0 i0Var = this.k;
            i0Var.getClass();
            ArrayList arrayList = new ArrayList();
            ReentrantLock reentrantLock = i0Var.a;
            reentrantLock.lock();
            try {
                Iterator it2 = i0Var.b.iterator();
                while (it2.hasNext()) {
                    com.braze.models.push.a aVar = (com.braze.models.push.a) it2.next();
                    if (arrayList.size() >= 32) {
                        break;
                    } else {
                        arrayList.add(aVar);
                    }
                }
                i0Var.b.removeAll(arrayList);
                reentrantLock.unlock();
                if (!arrayList.isEmpty()) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(29), 7, (Object) null);
                    a(new com.braze.requests.q(this.f, this.e.getBaseUrlForRequests(), this.b, arrayList));
                    return;
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(0), 7, (Object) null);
                    return;
                }
            } catch (Throwable th) {
                reentrantLock.unlock();
                throw th;
            }
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(5, j), 7, (Object) null);
        alarmManager.set(2, SystemClock.elapsedRealtime() + j, broadcast);
    }

    public final void a(String campaignId) {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(campaignId, 11), 7, (Object) null);
        this.k.a(campaignId);
    }
}
