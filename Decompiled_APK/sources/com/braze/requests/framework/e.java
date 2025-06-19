package com.braze.requests.framework;

import com.braze.H;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements c {
    public final /* synthetic */ g a;
    public final /* synthetic */ h b;
    public final /* synthetic */ b c;

    public e(g gVar, h hVar, b bVar) {
        this.a = gVar;
        this.b = hVar;
        this.c = bVar;
    }

    @Override // com.braze.requests.framework.c
    public final void a(com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        ReentrantLock reentrantLock = this.a.g;
        h hVar = this.b;
        b bVar = this.c;
        reentrantLock.lock();
        try {
            long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, g.n, (BrazeLogger.Priority) null, (Throwable) null, true, (Function0) new l(hVar, jNowInMillisecondsSystemClock, 1), 6, (Object) null);
            hVar.a(jNowInMillisecondsSystemClock, i.e);
            bVar.a(jNowInMillisecondsSystemClock, hVar, apiResponse);
            Unit unit = Unit.a;
        } finally {
            reentrantLock.unlock();
        }
    }

    public static final String a(h hVar, long j) {
        return "Request success received for " + hVar.a(j);
    }

    @Override // com.braze.requests.framework.c
    public final void a(com.braze.models.response.a apiResponse) {
        g gVar;
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        g gVar2 = this.a;
        ReentrantLock reentrantLock = gVar2.g;
        h hVar = this.b;
        b bVar = this.c;
        reentrantLock.lock();
        try {
            long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
            com.braze.models.response.g gVar3 = apiResponse instanceof com.braze.models.response.g ? (com.braze.models.response.g) apiResponse : null;
            com.braze.models.response.d dVar = gVar3 != null ? gVar3.d : null;
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, g.n, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new H(hVar, jNowInMillisecondsSystemClock, dVar, 1), 14, (Object) null);
            hVar.a(jNowInMillisecondsSystemClock, i.b);
            bVar.a(jNowInMillisecondsSystemClock, hVar, apiResponse);
            if (dVar instanceof com.braze.models.response.h) {
                gVar2.i = jNowInMillisecondsSystemClock;
                gVar2.h = ((com.braze.requests.b) ((com.braze.models.response.h) dVar).a).i;
                gVar = gVar2;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new H(gVar2, hVar, jNowInMillisecondsSystemClock, 2), 7, (Object) null);
                gVar.j = jNowInMillisecondsSystemClock + g.o;
            } else {
                gVar = gVar2;
            }
            if (dVar instanceof com.braze.models.response.e) {
                gVar.k.incrementAndGet();
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(gVar, 0), 7, (Object) null);
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String a(h hVar, long j, com.braze.models.response.d dVar) {
        return "Request failure received " + hVar.a(j) + " \n" + dVar;
    }

    public static final String a(g gVar, h hVar, long j) {
        return "Got failed token " + gVar.h + " for\n " + hVar.a(j);
    }

    public static final String a(g gVar) {
        return "Incremented invalidApiKeyErrorCounter to " + gVar.k.get();
    }
}
