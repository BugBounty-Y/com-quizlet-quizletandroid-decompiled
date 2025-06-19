package androidx.lifecycle;

import java.util.Map;

/* loaded from: classes.dex */
public abstract class T {
    public static final Object k = new Object();
    public final Object a;
    public final androidx.arch.core.internal.f b;
    public int c;
    public boolean d;
    public volatile Object e;
    public volatile Object f;
    public int g;
    public boolean h;
    public boolean i;
    public final O j;

    public T(Object obj) {
        this.a = new Object();
        this.b = new androidx.arch.core.internal.f();
        this.c = 0;
        this.f = k;
        this.j = new O(this);
        this.e = obj;
        this.g = 0;
    }

    public static void a(String str) {
        if (!androidx.arch.core.executor.b.p().a.q()) {
            throw new IllegalStateException(android.support.v4.media.session.a.B("Cannot invoke ", str, " on a background thread"));
        }
    }

    public final void b(S s) {
        if (s.b) {
            if (!s.e()) {
                s.a(false);
                return;
            }
            int i = s.c;
            int i2 = this.g;
            if (i >= i2) {
                return;
            }
            s.c = i2;
            s.a.a(this.e);
        }
    }

    public final void c(S s) {
        if (this.h) {
            this.i = true;
            return;
        }
        this.h = true;
        do {
            this.i = false;
            if (s != null) {
                b(s);
                s = null;
            } else {
                androidx.arch.core.internal.f fVar = this.b;
                fVar.getClass();
                androidx.arch.core.internal.d dVar = new androidx.arch.core.internal.d(fVar);
                fVar.c.put(dVar, Boolean.FALSE);
                while (dVar.hasNext()) {
                    b((S) ((Map.Entry) dVar.next()).getValue());
                    if (this.i) {
                        break;
                    }
                }
            }
        } while (this.i);
        this.h = false;
    }

    public Object d() {
        Object obj = this.e;
        if (obj != k) {
            return obj;
        }
        return null;
    }

    public final boolean e() {
        return this.c > 0;
    }

    public void f(J j, Z z) {
        Object obj;
        a("observe");
        if (((L) j.getLifecycle()).d == B.a) {
            return;
        }
        Q q = new Q(this, j, z);
        androidx.arch.core.internal.f fVar = this.b;
        androidx.arch.core.internal.c cVarA = fVar.a(z);
        if (cVarA != null) {
            obj = cVarA.b;
        } else {
            androidx.arch.core.internal.c cVar = new androidx.arch.core.internal.c(z, q);
            fVar.d++;
            androidx.arch.core.internal.c cVar2 = fVar.b;
            if (cVar2 == null) {
                fVar.a = cVar;
                fVar.b = cVar;
            } else {
                cVar2.c = cVar;
                cVar.d = cVar2;
                fVar.b = cVar;
            }
            obj = null;
        }
        S s = (S) obj;
        if (s != null && !s.c(j)) {
            throw new IllegalArgumentException("Cannot add the same observer with different lifecycles");
        }
        if (s != null) {
            return;
        }
        j.getLifecycle().a(q);
    }

    public final void g(Z z) {
        Object obj;
        a("observeForever");
        P p = new P(this, z);
        androidx.arch.core.internal.f fVar = this.b;
        androidx.arch.core.internal.c cVarA = fVar.a(z);
        if (cVarA != null) {
            obj = cVarA.b;
        } else {
            androidx.arch.core.internal.c cVar = new androidx.arch.core.internal.c(z, p);
            fVar.d++;
            androidx.arch.core.internal.c cVar2 = fVar.b;
            if (cVar2 == null) {
                fVar.a = cVar;
                fVar.b = cVar;
            } else {
                cVar2.c = cVar;
                cVar.d = cVar2;
                fVar.b = cVar;
            }
            obj = null;
        }
        S s = (S) obj;
        if (s instanceof Q) {
            throw new IllegalArgumentException("Cannot add the same observer with different lifecycles");
        }
        if (s != null) {
            return;
        }
        p.a(true);
    }

    public void h() {
    }

    public void i() {
    }

    public void j(Object obj) {
        boolean z;
        synchronized (this.a) {
            z = this.f == k;
            this.f = obj;
        }
        if (z) {
            androidx.arch.core.executor.b.p().q(this.j);
        }
    }

    public void k(Z z) {
        a("removeObserver");
        S s = (S) this.b.b(z);
        if (s == null) {
            return;
        }
        s.b();
        s.a(false);
    }

    public void l(Object obj) {
        a("setValue");
        this.g++;
        this.e = obj;
        c(null);
    }

    public T() {
        this.a = new Object();
        this.b = new androidx.arch.core.internal.f();
        this.c = 0;
        Object obj = k;
        this.f = obj;
        this.j = new O(this);
        this.e = obj;
        this.g = -1;
    }
}
