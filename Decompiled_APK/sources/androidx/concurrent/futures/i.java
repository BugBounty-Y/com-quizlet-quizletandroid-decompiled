package androidx.concurrent.futures;

import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class i {
    public Object a;
    public l b;
    public n c;
    public boolean d;

    public final void a(Runnable runnable, Executor executor) {
        n nVar = this.c;
        if (nVar != null) {
            nVar.a(runnable, executor);
        }
    }

    public final boolean b(Object obj) {
        this.d = true;
        l lVar = this.b;
        boolean z = lVar != null && lVar.b.k(obj);
        if (z) {
            this.a = null;
            this.b = null;
            this.c = null;
        }
        return z;
    }

    public final void c() {
        this.d = true;
        l lVar = this.b;
        if (lVar == null || !lVar.b.cancel(true)) {
            return;
        }
        this.a = null;
        this.b = null;
        this.c = null;
    }

    public final boolean d(Throwable th) {
        this.d = true;
        l lVar = this.b;
        boolean z = lVar != null && lVar.b.l(th);
        if (z) {
            this.a = null;
            this.b = null;
            this.c = null;
        }
        return z;
    }

    public final void finalize() {
        n nVar;
        l lVar = this.b;
        if (lVar != null) {
            k kVar = lVar.b;
            if (!kVar.isDone()) {
                kVar.l(new b("The completer object was garbage collected - this future would otherwise never complete. The tag was: " + this.a, 1));
            }
        }
        if (this.d || (nVar = this.c) == null) {
            return;
        }
        nVar.k(null);
    }
}
