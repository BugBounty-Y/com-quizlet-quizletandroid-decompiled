package androidx.room;

import androidx.lifecycle.T;
import androidx.work.impl.WorkDatabase_Impl;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class w extends T {
    public final WorkDatabase_Impl l;
    public final com.quizlet.data.repository.searchexplanations.c m;
    public final boolean n;
    public final androidx.work.impl.model.s o;
    public final c p;
    public final AtomicBoolean q;
    public final AtomicBoolean r;
    public final AtomicBoolean s;
    public final v t;
    public final v u;

    public w(WorkDatabase_Impl database, com.quizlet.data.repository.searchexplanations.c container, androidx.work.impl.model.s computeFunction, String[] tableNames) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(computeFunction, "computeFunction");
        Intrinsics.checkNotNullParameter(tableNames, "tableNames");
        this.l = database;
        this.m = container;
        this.n = true;
        this.o = computeFunction;
        this.p = new c(tableNames, this, 1);
        this.q = new AtomicBoolean(true);
        this.r = new AtomicBoolean(false);
        this.s = new AtomicBoolean(false);
        this.t = new v(this, 0);
        this.u = new v(this, 1);
    }

    @Override // androidx.lifecycle.T
    public final void h() {
        Executor executor;
        com.quizlet.data.repository.searchexplanations.c cVar = this.m;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(this, "liveData");
        ((Set) cVar.c).add(this);
        boolean z = this.n;
        WorkDatabase_Impl workDatabase_Impl = this.l;
        if (z) {
            executor = workDatabase_Impl.c;
            if (executor == null) {
                Intrinsics.m("internalTransactionExecutor");
                throw null;
            }
        } else {
            executor = workDatabase_Impl.b;
            if (executor == null) {
                Intrinsics.m("internalQueryExecutor");
                throw null;
            }
        }
        executor.execute(this.t);
    }

    @Override // androidx.lifecycle.T
    public final void i() {
        com.quizlet.data.repository.searchexplanations.c cVar = this.m;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(this, "liveData");
        ((Set) cVar.c).remove(this);
    }
}
