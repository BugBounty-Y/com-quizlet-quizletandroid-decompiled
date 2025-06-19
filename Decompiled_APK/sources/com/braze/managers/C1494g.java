package com.braze.managers;

import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.support.BrazeLogger;
import java.util.Iterator;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.managers.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1494g {
    public static void a() {
        ReentrantLock reentrantLock = C1495h.n;
        reentrantLock.lock();
        try {
            Iterator it2 = C1495h.o.iterator();
            if (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) C1495h.k, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(8), 6, (Object) null);
                throw null;
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            b();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static void b() {
        if (C1495h.m != null) {
            return;
        }
        C1495h.m = BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, 200L, null, new C1493f(null), 2, null);
    }

    public static final String c(AbstractC1491d abstractC1491d) {
        throw null;
    }
}
