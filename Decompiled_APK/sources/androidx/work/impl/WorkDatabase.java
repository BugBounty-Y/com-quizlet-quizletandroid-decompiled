package androidx.work.impl;

import android.database.Cursor;
import android.os.Looper;
import androidx.appcompat.app.ExecutorC0060p;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.collections.M;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class WorkDatabase {
    public volatile androidx.sqlite.db.framework.b a;
    public Executor b;
    public ExecutorC0060p c;
    public androidx.sqlite.db.e d;
    public boolean f;
    public ArrayList g;
    public final Map k;
    public final LinkedHashMap l;
    public final androidx.room.n e = d();
    public final LinkedHashMap h = new LinkedHashMap();
    public final ReentrantReadWriteLock i = new ReentrantReadWriteLock();
    public final ThreadLocal j = new ThreadLocal();

    public WorkDatabase() {
        Map mapSynchronizedMap = Collections.synchronizedMap(new LinkedHashMap());
        Intrinsics.checkNotNullExpressionValue(mapSynchronizedMap, "synchronizedMap(mutableMapOf())");
        this.k = mapSynchronizedMap;
        this.l = new LinkedHashMap();
    }

    public static Object r(Class cls, androidx.sqlite.db.e eVar) {
        if (cls.isInstance(eVar)) {
            return eVar;
        }
        if (eVar instanceof androidx.room.g) {
            return r(cls, ((androidx.room.g) eVar).getDelegate());
        }
        return null;
    }

    public final void a() {
        if (!this.f && Looper.getMainLooper().getThread() == Thread.currentThread()) {
            throw new IllegalStateException("Cannot access database on the main thread since it may potentially lock the UI for a long period of time.");
        }
    }

    public final void b() {
        if (!h().I().p() && this.j.get() != null) {
            throw new IllegalStateException("Cannot access database on a different coroutine context inherited from a suspending transaction.");
        }
    }

    public final void c() {
        a();
        a();
        androidx.sqlite.db.framework.b bVarI = h().I();
        this.e.f(bVarI);
        if (bVarI.q()) {
            bVarI.d();
        } else {
            bVarI.a();
        }
    }

    public abstract androidx.room.n d();

    public abstract androidx.sqlite.db.e e(androidx.room.f fVar);

    public abstract androidx.work.impl.model.c f();

    public List g(LinkedHashMap autoMigrationSpecs) {
        Intrinsics.checkNotNullParameter(autoMigrationSpecs, "autoMigrationSpecs");
        return K.a;
    }

    public final androidx.sqlite.db.e h() {
        androidx.sqlite.db.e eVar = this.d;
        if (eVar != null) {
            return eVar;
        }
        Intrinsics.m("internalOpenHelper");
        throw null;
    }

    public Set i() {
        return M.a;
    }

    public Map j() {
        return V.c();
    }

    public final void k() {
        h().I().i();
        if (h().I().p()) {
            return;
        }
        androidx.room.n nVar = this.e;
        if (nVar.f.compareAndSet(false, true)) {
            Executor executor = nVar.a.b;
            if (executor != null) {
                executor.execute(nVar.n);
            } else {
                Intrinsics.m("internalQueryExecutor");
                throw null;
            }
        }
    }

    public abstract androidx.work.impl.model.e l();

    public final Cursor m(androidx.sqlite.db.g query) {
        Intrinsics.checkNotNullParameter(query, "query");
        a();
        b();
        return h().I().r(query);
    }

    public final Object n(Callable body) {
        Intrinsics.checkNotNullParameter(body, "body");
        c();
        try {
            Object objCall = body.call();
            p();
            return objCall;
        } finally {
            k();
        }
    }

    public final void o(Runnable body) {
        Intrinsics.checkNotNullParameter(body, "body");
        c();
        try {
            body.run();
            p();
        } finally {
            k();
        }
    }

    public final void p() {
        h().I().B();
    }

    public abstract androidx.work.impl.model.i q();

    public abstract androidx.work.impl.model.l s();

    public abstract androidx.work.impl.model.n t();

    public abstract androidx.work.impl.model.t u();

    public abstract androidx.work.impl.model.v v();
}
