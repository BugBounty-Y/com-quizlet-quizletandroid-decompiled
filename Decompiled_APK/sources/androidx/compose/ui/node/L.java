package androidx.compose.ui.node;

import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L {
    public final E a;
    public boolean b;
    public boolean d;
    public boolean e;
    public boolean f;
    public boolean g;
    public boolean h;
    public boolean i;
    public int j;
    public int k;
    public boolean l;
    public boolean m;
    public int n;
    public boolean o;
    public boolean p;
    public int q;
    public J s;
    public int c = 5;
    public final K r = new K(this);
    public long t = L5.b(0, 0, 15);
    public final androidx.compose.ui.input.nestedscroll.b u = new androidx.compose.ui.input.nestedscroll.b(this, 6);

    public L(E e) {
        this.a = e;
    }

    public final a0 a() {
        return (a0) this.a.w.d;
    }

    public final void b(int i) {
        int i2 = this.n;
        this.n = i;
        if ((i2 == 0) != (i == 0)) {
            E eS = this.a.s();
            L l = eS != null ? eS.x : null;
            if (l != null) {
                if (i == 0) {
                    l.b(l.n - 1);
                } else {
                    l.b(l.n + 1);
                }
            }
        }
    }

    public final void c(int i) {
        int i2 = this.q;
        this.q = i;
        if ((i2 == 0) != (i == 0)) {
            E eS = this.a.s();
            L l = eS != null ? eS.x : null;
            if (l != null) {
                if (i == 0) {
                    l.c(l.q - 1);
                } else {
                    l.c(l.q + 1);
                }
            }
        }
    }

    public final void d(boolean z) {
        if (this.m != z) {
            this.m = z;
            if (z && !this.l) {
                b(this.n + 1);
            } else {
                if (z || this.l) {
                    return;
                }
                b(this.n - 1);
            }
        }
    }

    public final void e(boolean z) {
        if (this.l != z) {
            this.l = z;
            if (z && !this.m) {
                b(this.n + 1);
            } else {
                if (z || this.m) {
                    return;
                }
                b(this.n - 1);
            }
        }
    }

    public final void f(boolean z) {
        if (this.p != z) {
            this.p = z;
            if (z && !this.o) {
                c(this.q + 1);
            } else {
                if (z || this.o) {
                    return;
                }
                c(this.q - 1);
            }
        }
    }

    public final void g(boolean z) {
        if (this.o != z) {
            this.o = z;
            if (z && !this.p) {
                c(this.q + 1);
            } else {
                if (z || this.p) {
                    return;
                }
                c(this.q - 1);
            }
        }
    }

    public final void h() {
        K k = this.r;
        Object obj = k.r;
        E e = this.a;
        L l = k.H;
        if ((obj != null || l.a().G() != null) && k.q) {
            k.q = false;
            k.r = l.a().G();
            E eS = e.s();
            if (eS != null) {
                E.T(eS, false, 7);
            }
        }
        J j = this.s;
        if (j != null) {
            Object obj2 = j.w;
            L l2 = j.y;
            if (obj2 == null) {
                P pU0 = l2.a().U0();
                Intrinsics.d(pU0);
                if (pU0.l.G() == null) {
                    return;
                }
            }
            if (j.v) {
                j.v = false;
                P pU02 = l2.a().U0();
                Intrinsics.d(pU02);
                j.w = pU02.l.G();
                if (AbstractC0910f.r(e)) {
                    E eS2 = e.s();
                    if (eS2 != null) {
                        E.T(eS2, false, 7);
                        return;
                    }
                    return;
                }
                E eS3 = e.s();
                if (eS3 != null) {
                    E.R(eS3, false, 7);
                }
            }
        }
    }
}
