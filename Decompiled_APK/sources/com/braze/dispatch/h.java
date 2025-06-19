package com.braze.dispatch;

import com.braze.enums.DeviceKey;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.events.IEventSubscriber;
import com.braze.managers.C1506t;
import com.braze.managers.C1507u;
import com.braze.managers.d0;
import com.braze.managers.u0;
import com.braze.models.o;
import com.braze.requests.q;
import com.braze.storage.h0;
import com.braze.storage.p;
import com.braze.storage.r;
import com.braze.support.BrazeLogger;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public static final g d = new g();
    public final u0 a;
    public final ConcurrentHashMap b;
    public final ConcurrentHashMap c;

    public h(u0 udm) {
        Intrinsics.checkNotNullParameter(udm, "udm");
        this.a = udm;
        this.b = new ConcurrentHashMap();
        this.c = new ConcurrentHashMap();
        udm.l.c(com.braze.events.internal.dispatchmanager.c.class, (IEventSubscriber) new m(this, 0));
    }

    public static final void a(h hVar, com.braze.events.internal.dispatchmanager.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<destruct>");
        com.braze.events.internal.dispatchmanager.b bVar = cVar.a;
        List<com.braze.models.i> events = cVar.b;
        o oVar = cVar.c;
        int iOrdinal = bVar.ordinal();
        if (iOrdinal == 0) {
            hVar.getClass();
            Intrinsics.checkNotNullParameter(events, "events");
            for (com.braze.models.i iVar : events) {
                hVar.c.putIfAbsent(((com.braze.models.outgoing.event.b) iVar).d, iVar);
            }
            return;
        }
        if (iOrdinal != 1) {
            if (iOrdinal != 2) {
                return;
            }
            hVar.a(oVar);
        } else {
            hVar.getClass();
            Intrinsics.checkNotNullParameter(events, "events");
            for (com.braze.models.i iVar2 : events) {
                hVar.b.putIfAbsent(((com.braze.models.outgoing.event.b) iVar2).d, iVar2);
            }
        }
    }

    public static final String b() {
        return "Push permissions were granted, but blocking automatic opt-in";
    }

    public static final String c() {
        return "Push permissions were granted, setting user push notifications to opt-in";
    }

    public static final String d() {
        return "Flushing pending events to dispatcher map";
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0053, code lost:
    
        com.braze.support.BrazeLogger.brazelog$default(r4, (java.lang.Object) r12, com.braze.support.BrazeLogger.Priority.I, (java.lang.Throwable) null, false, (kotlin.jvm.functions.Function0) new com.braze.configuration.h(16), 6, (java.lang.Object) null);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized com.braze.models.b e() throws java.lang.Throwable {
        /*
            r12 = this;
            monitor-enter(r12)
            java.util.concurrent.ConcurrentHashMap r0 = r12.b     // Catch: java.lang.Throwable -> L59
            java.util.Collection r0 = r0.values()     // Catch: java.lang.Throwable -> L59
            java.lang.String r1 = "<get-values>(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)     // Catch: java.lang.Throwable -> L59
            java.util.LinkedHashSet r1 = new java.util.LinkedHashSet     // Catch: java.lang.Throwable -> L59
            r1.<init>()     // Catch: java.lang.Throwable -> L59
            java.util.Iterator r2 = r0.iterator()     // Catch: java.lang.Throwable -> L59
        L15:
            boolean r3 = r2.hasNext()     // Catch: java.lang.Throwable -> L59
            if (r3 == 0) goto L5e
            java.lang.Object r3 = r2.next()     // Catch: java.lang.Throwable -> L59
            java.lang.String r4 = "next(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)     // Catch: java.lang.Throwable -> L59
            com.braze.models.i r3 = (com.braze.models.i) r3     // Catch: java.lang.Throwable -> L59
            r1.add(r3)     // Catch: java.lang.Throwable -> L59
            r0.remove(r3)     // Catch: java.lang.Throwable -> L59
            com.braze.support.BrazeLogger r4 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Throwable -> L59
            com.braze.dispatch.n r9 = new com.braze.dispatch.n     // Catch: java.lang.Throwable -> L59
            r5 = 0
            r9.<init>(r3, r5)     // Catch: java.lang.Throwable -> L59
            r7 = 0
            r8 = 0
            r10 = 7
            r11 = 0
            r6 = 0
            r5 = r12
            com.braze.support.BrazeLogger.brazelog$default(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L57
            int r3 = r1.size()     // Catch: java.lang.Throwable -> L59
            r5 = 32
            if (r3 < r5) goto L5c
            com.braze.support.BrazeLogger$Priority r6 = com.braze.support.BrazeLogger.Priority.I     // Catch: java.lang.Throwable -> L59
            com.braze.configuration.h r9 = new com.braze.configuration.h     // Catch: java.lang.Throwable -> L59
            r0 = 16
            r9.<init>(r0)     // Catch: java.lang.Throwable -> L59
            r7 = 0
            r8 = 0
            r10 = 6
            r11 = 0
            r5 = r12
            com.braze.support.BrazeLogger.brazelog$default(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L57
            goto L5f
        L57:
            r0 = move-exception
            goto L66
        L59:
            r0 = move-exception
            r5 = r12
            goto L66
        L5c:
            r5 = r12
            goto L15
        L5e:
            r5 = r12
        L5f:
            com.braze.models.b r0 = new com.braze.models.b     // Catch: java.lang.Throwable -> L57
            r0.<init>(r1)     // Catch: java.lang.Throwable -> L57
            monitor-exit(r12)
            return r0
        L66:
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L57
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.dispatch.h.e():com.braze.models.b");
    }

    public final void a(com.braze.requests.f dataSyncRequest) throws Throwable {
        Intrinsics.checkNotNullParameter(dataSyncRequest, "dataSyncRequest");
        u0 u0Var = this.a;
        dataSyncRequest.o = ((C1506t) u0Var.e).c;
        dataSyncRequest.k = u0Var.b.getSdkFlavor();
        dataSyncRequest.p = ((C1506t) this.a.e).c();
        u0 u0Var2 = this.a;
        d0 d0Var = u0Var2.e;
        r deviceCache = u0Var2.k;
        String strForJsonPut = null;
        if (deviceCache != null) {
            C1506t c1506t = (C1506t) d0Var;
            c1506t.getClass();
            Intrinsics.checkNotNullParameter(deviceCache, "deviceCache");
            deviceCache.e = c1506t.b();
            com.braze.models.outgoing.h hVar = (com.braze.models.outgoing.h) deviceCache.a();
            dataSyncRequest.h = hVar;
            if (hVar != null && hVar.m) {
                if (this.a.b.getShouldOptInWhenPushAuthorized()) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.configuration.h(14), 6, (Object) null);
                    h0 h0VarA = this.a.a();
                    NotificationSubscriptionType notificationSubscriptionType = NotificationSubscriptionType.OPTED_IN;
                    synchronized (h0VarA) {
                        if (notificationSubscriptionType != null) {
                            try {
                                strForJsonPut = notificationSubscriptionType.forJsonPut();
                            } catch (Throwable th) {
                                throw th;
                            }
                        }
                        h0VarA.c("push_subscribe", strForJsonPut);
                    }
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.configuration.h(15), 6, (Object) null);
                }
            }
            if (hVar != null && hVar.forJsonPut().has(DeviceKey.NOTIFICATIONS_ENABLED.getKey())) {
                this.a.a().j();
            }
            dataSyncRequest.l = (com.braze.models.outgoing.l) this.a.a().a();
            com.braze.models.b bVarE = e();
            dataSyncRequest.m = bVarE;
            LinkedHashSet linkedHashSet = bVarE.a;
            if (linkedHashSet.isEmpty()) {
                return;
            }
            Iterator it2 = linkedHashSet.iterator();
            while (it2.hasNext()) {
                if (((com.braze.models.outgoing.event.b) ((com.braze.models.i) it2.next())).a == com.braze.enums.e.B) {
                    u0 u0Var3 = this.a;
                    dataSyncRequest.n = u0Var3.v.b(u0Var3.b.getSdkMetadata());
                    return;
                }
            }
            return;
        }
        Intrinsics.m("deviceCache");
        throw null;
    }

    public static final String a(com.braze.models.i iVar) {
        StringBuilder sb = new StringBuilder("Event dispatched: ");
        com.braze.models.outgoing.event.b bVar = (com.braze.models.outgoing.event.b) iVar;
        sb.append(bVar.forJsonPut());
        sb.append(" with uid: ");
        sb.append(bVar.d);
        return sb.toString();
    }

    public static final String a() {
        return "Max number of events per dispatch reached: 32 . No more events will be included in this dispatch";
    }

    public final void a(o oVar) {
        if (oVar != null) {
            ConcurrentHashMap concurrentHashMap = this.c;
            if (!concurrentHashMap.isEmpty()) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.configuration.h(13), 7, (Object) null);
                Collection collectionValues = concurrentHashMap.values();
                Intrinsics.checkNotNullExpressionValue(collectionValues, "<get-values>(...)");
                Iterator it2 = collectionValues.iterator();
                while (it2.hasNext()) {
                    ((com.braze.models.outgoing.event.b) ((com.braze.models.i) it2.next())).a(oVar);
                }
                this.b.putAll(concurrentHashMap);
                Set setKeySet = concurrentHashMap.keySet();
                Intrinsics.checkNotNullExpressionValue(setKeySet, "<get-keys>(...)");
                Iterator it3 = setKeySet.iterator();
                while (it3.hasNext()) {
                    this.c.remove((String) it3.next());
                }
            }
        }
    }

    public final com.braze.requests.n a(com.braze.requests.n brazeRequest) {
        Intrinsics.checkNotNullParameter(brazeRequest, "brazeRequest");
        g gVar = d;
        u0 u0Var = this.a;
        gVar.a(u0Var.b, u0Var.t, brazeRequest, ((C1507u) u0Var.c).a());
        if (brazeRequest instanceof com.braze.requests.f) {
            a((com.braze.requests.f) brazeRequest);
            return brazeRequest;
        }
        if (brazeRequest instanceof q) {
            ((q) brazeRequest).h = ((C1506t) this.a.e).b();
            return brazeRequest;
        }
        if (brazeRequest instanceof com.braze.requests.e) {
            p pVar = this.a.C;
            com.braze.requests.e eVar = (com.braze.requests.e) brazeRequest;
            eVar.j = pVar.c;
            eVar.k = pVar.d;
        }
        return brazeRequest;
    }
}
