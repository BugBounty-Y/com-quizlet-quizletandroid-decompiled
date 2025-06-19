package com.google.android.gms.tasks;

import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.C3083y1;
import java.io.IOException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class m extends Task {
    public final Object a = new Object();
    public final C3083y1 b = new C3083y1(8);
    public boolean c;
    public volatile boolean d;
    public Object e;
    public Exception f;

    @Override // com.google.android.gms.tasks.Task
    public final void a(Executor executor, b bVar) {
        this.b.j(new j(executor, bVar));
        u();
    }

    @Override // com.google.android.gms.tasks.Task
    public final Task addOnCompleteListener(OnCompleteListener onCompleteListener) {
        this.b.j(new j(g.a, onCompleteListener));
        u();
        return this;
    }

    @Override // com.google.android.gms.tasks.Task
    public final void b(Executor executor, OnCompleteListener onCompleteListener) {
        this.b.j(new j(executor, onCompleteListener));
        u();
    }

    @Override // com.google.android.gms.tasks.Task
    public final m c(Executor executor, c cVar) {
        this.b.j(new j(executor, cVar));
        u();
        return this;
    }

    @Override // com.google.android.gms.tasks.Task
    public final m d(Executor executor, d dVar) {
        this.b.j(new j(executor, dVar));
        u();
        return this;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Task e(Executor executor, a aVar) {
        m mVar = new m();
        this.b.j(new i(executor, aVar, mVar, 0));
        u();
        return mVar;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Task f(Executor executor, a aVar) {
        m mVar = new m();
        this.b.j(new i(executor, aVar, mVar, 1));
        u();
        return mVar;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Exception g() {
        Exception exc;
        synchronized (this.a) {
            exc = this.f;
        }
        return exc;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Object h() {
        Object obj;
        synchronized (this.a) {
            try {
                u.j("Task is not yet complete", this.c);
                if (this.d) {
                    throw new CancellationException("Task is already canceled.");
                }
                Exception exc = this.f;
                if (exc != null) {
                    throw new RuntimeExecutionException(exc);
                }
                obj = this.e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return obj;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Object i() {
        Object obj;
        synchronized (this.a) {
            try {
                u.j("Task is not yet complete", this.c);
                if (this.d) {
                    throw new CancellationException("Task is already canceled.");
                }
                if (IOException.class.isInstance(this.f)) {
                    throw ((Throwable) IOException.class.cast(this.f));
                }
                Exception exc = this.f;
                if (exc != null) {
                    throw new RuntimeExecutionException(exc);
                }
                obj = this.e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return obj;
    }

    @Override // com.google.android.gms.tasks.Task
    public final boolean j() {
        return this.d;
    }

    @Override // com.google.android.gms.tasks.Task
    public final boolean k() {
        boolean z;
        synchronized (this.a) {
            z = this.c;
        }
        return z;
    }

    @Override // com.google.android.gms.tasks.Task
    public final boolean l() {
        boolean z;
        synchronized (this.a) {
            try {
                z = false;
                if (this.c && !this.d && this.f == null) {
                    z = true;
                }
            } finally {
            }
        }
        return z;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Task m(e eVar) {
        androidx.camera.core.impl.utils.executor.h hVar = g.a;
        m mVar = new m();
        this.b.j(new j(hVar, eVar, mVar));
        u();
        return mVar;
    }

    @Override // com.google.android.gms.tasks.Task
    public final Task n(Executor executor, e eVar) {
        m mVar = new m();
        this.b.j(new j(executor, eVar, mVar));
        u();
        return mVar;
    }

    public final m o(c cVar) {
        c(g.a, cVar);
        return this;
    }

    public final void p(Object obj) {
        synchronized (this.a) {
            t();
            this.c = true;
            this.e = obj;
        }
        this.b.k(this);
    }

    public final boolean q(Object obj) {
        synchronized (this.a) {
            try {
                if (this.c) {
                    return false;
                }
                this.c = true;
                this.e = obj;
                this.b.k(this);
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void r(Exception exc) {
        u.i(exc, "Exception must not be null");
        synchronized (this.a) {
            t();
            this.c = true;
            this.f = exc;
        }
        this.b.k(this);
    }

    public final void s() {
        synchronized (this.a) {
            try {
                if (this.c) {
                    return;
                }
                this.c = true;
                this.d = true;
                this.b.k(this);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void t() {
        if (this.c) {
            int i = DuplicateTaskCompletionException.a;
            if (!k()) {
                throw new IllegalStateException("DuplicateTaskCompletionException can only be created from completed Task.");
            }
            Exception excG = g();
        }
    }

    public final void u() {
        synchronized (this.a) {
            try {
                if (this.c) {
                    this.b.k(this);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
