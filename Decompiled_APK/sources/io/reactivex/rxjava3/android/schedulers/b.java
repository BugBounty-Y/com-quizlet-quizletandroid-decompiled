package io.reactivex.rxjava3.android.schedulers;

import io.reactivex.rxjava3.core.o;

/* loaded from: classes3.dex */
public abstract class b {
    public static final o a;

    static {
        try {
            e eVar = a.a;
            if (eVar == null) {
                throw new NullPointerException("Scheduler Callable returned null");
            }
            a = eVar;
        } catch (Throwable th) {
            throw io.reactivex.rxjava3.internal.util.c.d(th);
        }
    }

    public static o a() {
        o oVar = a;
        if (oVar != null) {
            return oVar;
        }
        throw new NullPointerException("scheduler == null");
    }
}
