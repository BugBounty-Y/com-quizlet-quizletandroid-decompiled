package com.braze.requests.framework;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.lifecycle.C1247h;
import com.braze.managers.u0;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;

/* loaded from: classes.dex */
public abstract class b {
    public static final String j = BrazeLogger.getBrazeLogTag((Class<?>) b.class);
    public final com.braze.requests.m a;
    public final com.braze.dispatch.h b;
    public long c;
    public long d;
    public final ArrayList e;
    public long f;
    public final long g;
    public final com.braze.requests.util.b h;
    public com.braze.requests.util.d i;

    public b(com.braze.requests.m destination, com.braze.dispatch.h dispatchDataProvider) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
        this.a = destination;
        this.b = dispatchDataProvider;
        this.e = new ArrayList();
        int iOrdinal = destination.ordinal();
        this.g = iOrdinal != 0 ? iOrdinal != 2 ? 0L : 75L : 25L;
        this.h = new com.braze.requests.util.b(dispatchDataProvider.a.m.j(), dispatchDataProvider.a.m.k(), dispatchDataProvider.a.m.l());
    }

    public static final String d(b bVar, long j2) {
        return "New state after request success\n" + bVar.d(j2);
    }

    public abstract void a(long j2);

    public final void a(long j2, com.braze.requests.n request) {
        Intrinsics.checkNotNullParameter(request, "request");
        request.a(this.b.a.l);
        this.e.add(new h(request, j2 + this.g, j2));
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this, (BrazeLogger.Priority) null, (Throwable) null, c(), new j(this, j2, 2), 3, (Object) null);
    }

    public final com.braze.requests.util.d b() {
        Map mapW;
        e0 e0Var = this.b.a.m;
        ReentrantLock reentrantLock = e0Var.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = e0Var.e;
            if (mVar == null || (mapW = mVar.E) == null) {
                mapW = e0Var.w();
            }
            reentrantLock.unlock();
            com.braze.models.response.j jVar = (com.braze.models.response.j) mapW.get(this.a);
            if (jVar == null) {
                this.i = null;
                return null;
            }
            com.braze.requests.util.d dVar = this.i;
            int i = jVar.b;
            int i2 = jVar.a;
            if (dVar == null) {
                com.braze.dispatch.h dispatchDataProvider = this.b;
                String specificName = String.valueOf(this.a.hashCode());
                Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
                Intrinsics.checkNotNullParameter("com.braze.endpointqueue.tokenbucket", "filePrefix");
                Intrinsics.checkNotNullParameter(specificName, "specificName");
                u0 u0Var = dispatchDataProvider.a;
                Context context = u0Var.a;
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.braze.endpointqueue.tokenbucket." + specificName + StringUtils.getCacheFileSuffix(context, u0Var.g, u0Var.h), 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
                dVar = new com.braze.requests.util.d(i2, i, sharedPreferences);
            } else {
                dVar.a(i2, i);
            }
            this.i = dVar;
            return dVar;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public boolean c() {
        return false;
    }

    public final void c(long j2) {
        ArrayList arrayList = this.e;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((h) next).d.a()) {
                arrayList2.add(next);
            }
        }
        List listN0 = CollectionsKt.n0(arrayList2, new a());
        if (listN0.size() >= 2) {
            int size = listN0.size();
            for (int i = 1; i < size; i++) {
                h hVar = (h) listN0.get(i);
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, j, (BrazeLogger.Priority) null, (Throwable) null, c(), (Function0) new C1247h(hVar, 29), 6, (Object) null);
                hVar.a(j2, i.d);
            }
        }
    }

    public final String d(long j2) {
        String string;
        String strS = CollectionsKt.S(this.e, "\n\n", null, null, new m(0, j2), 30);
        StringBuilder sb = new StringBuilder("\n            |EndpointQueue: ");
        sb.append(this.a);
        sb.append("\n            |   lastFailureAt = ");
        sb.append(this.c - j2);
        sb.append("\n            |   lastSuccessAt = ");
        sb.append(this.d - j2);
        sb.append("\n            |   failureBackoffUntil = ");
        sb.append(this.f - j2);
        sb.append("\n            |   pendingWaitDuration = ");
        sb.append(this.g);
        sb.append("\n            |   endpointRateLimiter = ");
        com.braze.requests.util.d dVar = this.i;
        if (dVar == null || (string = dVar.toString()) == null) {
            string = "unset";
        }
        sb.append(string);
        sb.append("\n            |   requestInfoQueue: \n            |");
        sb.append(strS);
        sb.append("\n        ");
        return x.d(sb.toString());
    }

    public com.braze.requests.util.b a() {
        return this.h;
    }

    public static final String a(b bVar, long j2) {
        return "Added request now to queue " + bVar.d(j2);
    }

    public static final String a(h hVar, long j2, int i) {
        return "Set retry count for " + hVar.a(j2) + " to " + i;
    }

    public static final String a(h hVar, long j2) {
        return "Marking request as framework complete \n" + hVar.a(j2);
    }

    public final void a(long j2, h requestInfo) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        com.braze.requests.util.d dVarB = b();
        if (dVarB == null) {
            return;
        }
        dVarB.a();
        com.braze.requests.util.d dVarB2 = b();
        if (dVarB2 != null && dVarB2.a(j2) < 1.0d) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this, (BrazeLogger.Priority) null, (Throwable) null, c(), new n(requestInfo, j2, dVarB.b(), dVarB, 0), 3, (Object) null);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(this, j2, 3), 7, (Object) null);
    }

    public static final String c(b bVar, long j2) {
        return "New state after request error " + bVar.d(j2);
    }

    public static final String a(h hVar, long j2, long j3, com.braze.requests.util.d dVar) {
        return "Delaying next request after '" + hVar.a(j2) + "' until next token is available in " + j3 + "ms - '" + DateTimeUtils.formatDateFromMillis$default(j2 + j3, null, null, 3, null) + "'\n" + dVar;
    }

    public static final String a(h hVar) {
        return "About to batch request " + hVar;
    }

    public void a(long j2, h requestInfo, com.braze.models.response.a apiResponse) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        com.braze.models.response.g gVar = apiResponse instanceof com.braze.models.response.g ? (com.braze.models.response.g) apiResponse : null;
        com.braze.models.response.d dVar = gVar != null ? gVar.d : null;
        Long l = apiResponse.b;
        long jLongValue = l != null ? l.longValue() : 0L;
        this.c = j2;
        if (!(dVar instanceof com.braze.models.response.h)) {
            com.braze.requests.util.b bVarA = a();
            this.f = jLongValue + j2 + bVarA.a(bVarA.b);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, j, (BrazeLogger.Priority) null, (Throwable) null, c(), (Function0) new j(this, j2, 1), 6, (Object) null);
    }

    public final void b(long j2) {
        int i;
        a(j2);
        ArrayList arrayList = this.e;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((h) next).d == i.d) {
                arrayList2.add(next);
            }
        }
        if (!arrayList2.isEmpty()) {
            Iterator it3 = arrayList2.iterator();
            if (it3.hasNext()) {
                int i2 = ((h) it3.next()).h;
                loop1: while (true) {
                    i = i2;
                    while (it3.hasNext()) {
                        i2 = ((h) it3.next()).h;
                        if (i < i2) {
                            break;
                        }
                    }
                }
                ArrayList arrayList3 = this.e;
                ArrayList arrayList4 = new ArrayList();
                Iterator it4 = arrayList3.iterator();
                while (it4.hasNext()) {
                    Object next2 = it4.next();
                    if (((h) next2).d.a()) {
                        arrayList4.add(next2);
                    }
                }
                Iterator it5 = arrayList4.iterator();
                while (it5.hasNext()) {
                    h hVar = (h) it5.next();
                    hVar.h = i;
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this, (BrazeLogger.Priority) null, (Throwable) null, c(), new k(i, 0, j2, hVar), 3, (Object) null);
                    i = i;
                }
            } else {
                throw new NoSuchElementException();
            }
        }
        ArrayList arrayList5 = new ArrayList();
        ArrayList arrayList6 = this.e;
        ArrayList arrayList7 = new ArrayList();
        Iterator it6 = arrayList6.iterator();
        while (it6.hasNext()) {
            Object next3 = it6.next();
            i iVar = ((h) next3).d;
            if (iVar == i.d || iVar == i.e) {
                arrayList7.add(next3);
            }
        }
        arrayList5.addAll(arrayList7);
        ArrayList arrayList8 = this.e;
        ArrayList arrayList9 = new ArrayList();
        Iterator it7 = arrayList8.iterator();
        while (it7.hasNext()) {
            Object next4 = it7.next();
            h hVar2 = (h) next4;
            if (hVar2.h >= 15 && hVar2.d.a()) {
                arrayList9.add(next4);
            }
        }
        arrayList5.addAll(arrayList9);
        Iterator it8 = arrayList5.iterator();
        while (it8.hasNext()) {
            h hVar3 = (h) it8.next();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, j, (BrazeLogger.Priority) null, (Throwable) null, c(), (Function0) new l(hVar3, j2, 0), 6, (Object) null);
            hVar3.a.a((com.braze.events.e) this.b.a.l);
        }
        this.e.removeAll(arrayList5);
    }

    public void a(long j2, h requestInfo, com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(requestInfo, "requestInfo");
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        a().f = 0;
        this.d = j2;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, j, (BrazeLogger.Priority) null, (Throwable) null, c(), (Function0) new j(this, j2, 0), 6, (Object) null);
    }

    public static final String b(b bVar, long j2) {
        return bVar.d(j2);
    }

    public static final CharSequence b(long j2, h it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.a(j2);
    }
}
