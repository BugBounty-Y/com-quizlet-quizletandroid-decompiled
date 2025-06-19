package com.google.android.gms.measurement.internal;

import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

/* loaded from: classes2.dex */
public final class V extends FutureTask implements Comparable {
    public final long a;
    public final boolean b;
    public final String c;
    public final /* synthetic */ X d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(X x, Runnable runnable, boolean z, String str) {
        super(runnable, null);
        this.d = x;
        long andIncrement = X.l.getAndIncrement();
        this.a = andIncrement;
        this.c = str;
        this.b = z;
        if (andIncrement == Long.MAX_VALUE) {
            I i = ((Y) x.b).i;
            Y.k(i);
            i.g.f("Tasks index overflow");
        }
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        V v = (V) obj;
        boolean z = v.b;
        boolean z2 = this.b;
        if (z2 != z) {
            return !z2 ? 1 : -1;
        }
        long j = this.a;
        long j2 = v.a;
        if (j < j2) {
            return -1;
        }
        if (j > j2) {
            return 1;
        }
        I i = ((Y) this.d.b).i;
        Y.k(i);
        i.h.g("Two tasks share the same index. index", Long.valueOf(j));
        return 0;
    }

    @Override // java.util.concurrent.FutureTask
    public final void setException(Throwable th) {
        I i = ((Y) this.d.b).i;
        Y.k(i);
        i.g.g(this.c, th);
        super.setException(th);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(X x, Callable callable, boolean z) {
        super(callable);
        this.d = x;
        long andIncrement = X.l.getAndIncrement();
        this.a = andIncrement;
        this.c = "Task exception on worker thread";
        this.b = z;
        if (andIncrement == Long.MAX_VALUE) {
            I i = ((Y) x.b).i;
            Y.k(i);
            i.g.f("Tasks index overflow");
        }
    }
}
