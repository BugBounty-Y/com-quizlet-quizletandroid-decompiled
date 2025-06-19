package com.google.android.gms.tasks;

import androidx.appcompat.app.L;
import androidx.appcompat.app.Q;
import androidx.webkit.internal.p;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public class f {
    public final m a = new m();

    public f() {
    }

    public final void a(Exception exc) {
        this.a.r(exc);
    }

    public final void b(Object obj) {
        this.a.p(obj);
    }

    public final boolean c(Exception exc) {
        m mVar = this.a;
        mVar.getClass();
        u.i(exc, "Exception must not be null");
        synchronized (mVar.a) {
            try {
                if (mVar.c) {
                    return false;
                }
                mVar.c = true;
                mVar.f = exc;
                mVar.b.k(mVar);
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d(Object obj) {
        this.a.q(obj);
    }

    public f(Q q) {
        p pVar = new p(this, 21);
        q.getClass();
        L l = new L(pVar, 24);
        ((m) q.a).d(g.a, l);
    }
}
