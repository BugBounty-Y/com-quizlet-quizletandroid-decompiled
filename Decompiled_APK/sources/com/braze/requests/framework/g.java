package com.braze.requests.framework;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import com.braze.AbstractC1477c;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IEventSubscriber;
import com.braze.managers.T;
import com.braze.managers.u0;
import com.braze.requests.u;
import com.braze.requests.y;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import kotlinx.coroutines.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.H;
import kotlinx.coroutines.I;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.q0;

/* loaded from: classes.dex */
public final class g {
    public static final String n = BrazeLogger.getBrazeLogTag((Class<?>) g.class);
    public static final long o = TimeUnit.HOURS.toMillis(1);
    public static final long p = TimeUnit.MINUTES.toMillis(1);
    public final com.braze.dispatch.h a;
    public final u b;
    public final boolean c;
    public final boolean d;
    public final LinkedHashMap e;
    public H f;
    public final ReentrantLock g;
    public String h;
    public long i;
    public long j;
    public final AtomicInteger k;
    public final com.braze.requests.util.d l;
    public com.braze.enums.f m;

    public g(com.braze.dispatch.h dispatchDataProvider, u requestExecutor, boolean z, boolean z2) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
        Intrinsics.checkNotNullParameter(requestExecutor, "requestExecutor");
        this.a = dispatchDataProvider;
        this.b = requestExecutor;
        this.c = z;
        this.d = z2;
        this.e = new LinkedHashMap();
        this.g = new ReentrantLock();
        this.i = -1L;
        this.j = -1L;
        this.k = new AtomicInteger(0);
        int iN = dispatchDataProvider.a.m.n();
        int iO = dispatchDataProvider.a.m.o();
        Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
        Intrinsics.checkNotNullParameter("com.braze.requestframework.tokenbucket", "filePrefix");
        Intrinsics.checkNotNullParameter("", "specificName");
        u0 u0Var = dispatchDataProvider.a;
        Context context = u0Var.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.braze.requestframework.tokenbucket." + StringUtils.getCacheFileSuffix(context, u0Var.g, u0Var.h), 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.l = new com.braze.requests.util.d(iN, iO, sharedPreferences);
        this.m = com.braze.enums.f.c;
        final int i = 0;
        dispatchDataProvider.a.l.c(com.braze.events.internal.dispatchmanager.c.class, new IEventSubscriber(this) { // from class: com.braze.requests.framework.r
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i) {
                    case 0:
                        g.a(this.b, (com.braze.events.internal.dispatchmanager.c) obj);
                        break;
                    default:
                        g.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                }
            }
        });
        final int i2 = 1;
        dispatchDataProvider.a.l.c(com.braze.events.internal.o.class, new IEventSubscriber(this) { // from class: com.braze.requests.framework.r
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                switch (i2) {
                    case 0:
                        g.a(this.b, (com.braze.events.internal.dispatchmanager.c) obj);
                        break;
                    default:
                        g.a(this.b, (com.braze.events.internal.o) obj);
                        break;
                }
            }
        });
    }

    public static final void a(g gVar, com.braze.events.internal.dispatchmanager.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<destruct>");
        com.braze.events.internal.dispatchmanager.b bVar = cVar.a;
        com.braze.requests.n nVar = cVar.d;
        ReentrantLock reentrantLock = gVar.g;
        reentrantLock.lock();
        try {
            if (bVar == com.braze.events.internal.dispatchmanager.b.d && nVar != null) {
                gVar.a(nVar);
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String b() {
        return "Starting request sweeper job.";
    }

    public static final String c() {
        return "Skipping request sending due to lacking a global request rate limiting token.";
    }

    public static final String d() {
        return "Skipping request sending due to lacking an endpoint request rate limiting token.";
    }

    public static final String f() {
        return "Got call to shutdown request framework";
    }

    public static final String h() {
        return "Kicking off request framework.";
    }

    public final void e() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, n, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(10), 14, (Object) null);
        InterfaceC5025j0 interfaceC5025j0 = this.f;
        if (interfaceC5025j0 != null) {
            ((q0) interfaceC5025j0).j(null);
        }
        u0 u0Var = this.a.a;
        com.braze.requests.f fVar = new com.braze.requests.f(u0Var.m, u0Var.b.getBaseUrlForRequests(), new com.braze.models.outgoing.k(null, null, null, null));
        this.a.a((com.braze.requests.n) fVar);
        long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
        a(jNowInMillisecondsSystemClock, fVar, new h(fVar, jNowInMillisecondsSystemClock, jNowInMillisecondsSystemClock), new f(), false);
    }

    public final void g() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(9), 7, (Object) null);
        a();
    }

    public static final String b(long j, h hVar) {
        StringBuilder sbT = d0.t(j, "Running at ", " for request ");
        sbT.append(hVar.a(j));
        return sbT.toString();
    }

    public static final String b(g gVar, long j) {
        return gVar.b(j);
    }

    public final void a(long j, b queue) {
        Intrinsics.checkNotNullParameter(queue, "queue");
        if (j <= queue.f) {
            return;
        }
        queue.b(j);
        ArrayList arrayList = queue.e;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            h hVar = (h) next;
            if (hVar.d.a() && j >= hVar.b) {
                arrayList2.add(next);
            }
        }
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            a(j, queue, (h) it3.next());
        }
    }

    public final String b(long j) {
        LinkedHashMap linkedHashMap = this.e;
        ArrayList arrayList = new ArrayList(linkedHashMap.size());
        Iterator it2 = linkedHashMap.entrySet().iterator();
        while (it2.hasNext()) {
            arrayList.add((b) ((Map.Entry) it2.next()).getValue());
        }
        String strS = CollectionsKt.S(arrayList, "\n\n", null, null, new m(1, j), 30);
        StringBuilder sb = new StringBuilder("RequestFramework->\n            |mockAllNetworkRequests=");
        sb.append(this.c);
        sb.append("\n            |lastSdkAuthFailedToken=");
        sb.append(this.h);
        sb.append("\n            |lastSdkAuthFailureAt=");
        sb.append(this.i - j);
        sb.append("\n            |sdkAuthFailureBackoffUntil=");
        sb.append(this.j - j);
        sb.append("\n            |invalidApiKeyErrorCounter=");
        sb.append(this.k.get());
        sb.append("\n            |globalRequestRateLimiter=");
        sb.append(this.l);
        sb.append("\n            |lastNetworkLevel=");
        sb.append(this.m);
        sb.append("\n            |currentSdkAuthToken=");
        sb.append(this.a.a.t.d.getString("auth_signature", null));
        sb.append("\n            |endpointQueues=\n            | \n            |");
        return x.d(AbstractC1477c.a(sb, strS, "\n            |  \n            |\n        "));
    }

    public static final void a(g gVar, com.braze.events.internal.o it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, n, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new T(it2, 1), 14, (Object) null);
        gVar.m = it2.b;
    }

    public static final String a(com.braze.events.internal.o oVar) {
        return "Got network change event: " + oVar;
    }

    public static void a(g gVar) {
        long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
        ReentrantLock reentrantLock = gVar.g;
        reentrantLock.lock();
        try {
            if ((!gVar.d || gVar.m != com.braze.enums.f.a) && ((gVar.h == null || jNowInMillisecondsSystemClock >= gVar.j || !Intrinsics.b(gVar.a.a.t.d.getString("auth_signature", null), gVar.h)) && gVar.a(jNowInMillisecondsSystemClock))) {
                Iterator it2 = gVar.e.entrySet().iterator();
                while (it2.hasNext()) {
                    gVar.a(jNowInMillisecondsSystemClock, (b) ((Map.Entry) it2.next()).getValue());
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final void a() {
        H h = this.f;
        if (h == null || !h.a()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new y(11), 6, (Object) null);
            BrazeCoroutineScope brazeCoroutineScope = BrazeCoroutineScope.INSTANCE;
            D d = D.a;
            I iF = E.f(brazeCoroutineScope, null, new d(this, null), 1);
            this.f = iF;
            iF.start();
        }
    }

    public static final CharSequence b(long j, b it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.d(j);
    }

    public final void a(long j, b queue, h requestInfo) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, this, (BrazeLogger.Priority) null, (Throwable) null, queue.c(), new l(j, requestInfo), 3, (Object) null);
        if (!a(j)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(12), 7, (Object) null);
            return;
        }
        com.braze.requests.util.d dVarB = queue.b();
        if (dVarB == null || dVarB.a(j) >= 1.0d) {
            com.braze.requests.n nVarA = this.a.a(requestInfo.a);
            Intrinsics.checkNotNullParameter(queue, "queue");
            Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
            e eVar = new e(this, requestInfo, queue);
            requestInfo.a(j, i.c);
            com.braze.requests.util.d dVarB2 = queue.b();
            Integer numValueOf = null;
            Integer numValueOf2 = dVarB2 == null ? null : Integer.valueOf((int) dVarB2.a(j));
            if (numValueOf2 != null) {
                int iIntValue = numValueOf2.intValue() - 1;
                if (iIntValue < 0) {
                    iIntValue = 0;
                }
                numValueOf = Integer.valueOf(iIntValue);
            }
            requestInfo.f = numValueOf;
            int iA = ((int) this.l.a(j)) - 1;
            requestInfo.e = iA >= 0 ? iA : 0;
            if (a(j, nVarA, requestInfo, eVar, false)) {
                return;
            }
            a(j, requestInfo);
            queue.a(j, requestInfo);
            return;
        }
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new y(13), 7, (Object) null);
        com.braze.requests.util.d dVarB3 = queue.b();
        requestInfo.b = (dVarB3 != null ? dVarB3.b() : 0L) + j;
    }

    public final boolean a(final long j, com.braze.requests.n nVar, final h hVar, c cVar, boolean z) {
        com.braze.requests.p pVar;
        final boolean z2 = nVar.a() || this.c;
        if (z2) {
            pVar = this.a.a.D;
        } else {
            pVar = this.b;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, true, new Function0() { // from class: com.braze.requests.framework.q
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                return g.a(z2, hVar, j);
            }
        }, 3, (Object) null);
        pVar.a(hVar, cVar, z);
        return z2;
    }

    public static final String a(boolean z, h hVar, long j) {
        StringBuilder sb = new StringBuilder("Running on ");
        sb.append(z ? "no-op" : "network");
        sb.append(" executor for ");
        sb.append(hVar.a(j));
        return sb.toString();
    }

    public final void a(com.braze.requests.n request) {
        b aVar;
        Intrinsics.checkNotNullParameter(request, "request");
        com.braze.requests.m mVarC = request.c();
        if (!this.e.containsKey(mVarC)) {
            int iOrdinal = mVarC.ordinal();
            if (iOrdinal == 0) {
                aVar = new com.braze.requests.framework.queue.a(this.a);
            } else if (iOrdinal == 1) {
                aVar = new com.braze.requests.framework.queue.f(this.a);
            } else if (iOrdinal == 2) {
                aVar = new com.braze.requests.framework.queue.c(this.a);
            } else if (iOrdinal != 3) {
                switch (iOrdinal) {
                    case 9:
                        aVar = new com.braze.requests.framework.queue.g(this.a);
                        break;
                    case 10:
                        aVar = new com.braze.requests.framework.queue.h(this.a);
                        break;
                    case 11:
                        aVar = new com.braze.requests.framework.queue.e(this.a);
                        break;
                    default:
                        aVar = new com.braze.requests.framework.queue.d(mVarC, this.a);
                        break;
                }
            } else {
                aVar = new com.braze.requests.framework.queue.i(this.a);
            }
            this.e.put(mVarC, aVar);
        } else {
            aVar = (b) this.e.get(mVarC);
        }
        if (aVar == null) {
            return;
        }
        long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
        aVar.a(jNowInMillisecondsSystemClock, request);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, true, (Function0) new p(this, jNowInMillisecondsSystemClock, 1), 3, (Object) null);
        a();
    }

    public static final String a(g gVar, long j) {
        return gVar.b(j);
    }

    public final void a(long j, h requestInfo) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        this.l.a();
        if (!a(j)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new n(requestInfo, j, this.l.b(), this, 1), 7, (Object) null);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, true, (Function0) new p(this, j, 0), 3, (Object) null);
    }

    public static final String a(h hVar, long j, long j2, g gVar) {
        return "Delaying next request after " + hVar.a(j) + " until next token is available in " + j2 + "ms - '" + DateTimeUtils.formatDateFromMillis$default(j + j2, null, null, 3, null) + "'\n" + gVar.l;
    }

    public final boolean a(long j) {
        return !this.a.a.m.J() || this.l.a(j) >= 1.0d;
    }
}
