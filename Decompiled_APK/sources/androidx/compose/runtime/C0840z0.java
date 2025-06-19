package androidx.compose.runtime;

import java.util.ArrayList;

/* renamed from: androidx.compose.runtime.z0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0840z0 {
    public final A0 a;
    public final int[] b;
    public final int c;
    public final Object[] d;
    public final int e;
    public boolean f;
    public int g;
    public int h;
    public int i;
    public final N j;
    public int k;
    public int l;
    public int m;
    public boolean n;

    public C0840z0(A0 a0) {
        this.a = a0;
        this.b = a0.a;
        int i = a0.b;
        this.c = i;
        this.d = a0.c;
        this.e = a0.d;
        this.h = i;
        this.i = -1;
        this.j = new N();
    }

    public final C0774b a(int i) {
        ArrayList arrayList = this.a.i;
        int iE = C0.e(arrayList, i, this.c);
        if (iE >= 0) {
            return (C0774b) arrayList.get(iE);
        }
        C0774b c0774b = new C0774b(i);
        arrayList.add(-(iE + 1), c0774b);
        return c0774b;
    }

    public final Object b(int[] iArr, int i) {
        int i2 = i * 5;
        int i3 = iArr[i2 + 1];
        if ((268435456 & i3) != 0) {
            return this.d[i2 >= iArr.length ? iArr.length : iArr[i2 + 4] + Integer.bitCount(i3 >> 29)];
        }
        return C0804k.a;
    }

    public final void c() {
        this.f = true;
        A0 a0 = this.a;
        a0.getClass();
        if (this.a != a0 || a0.e <= 0) {
            r.c("Unexpected reader close()");
        }
        a0.e--;
    }

    public final boolean d(int i) {
        return (this.b[(i * 5) + 1] & 67108864) != 0;
    }

    public final void e() {
        if (this.k == 0) {
            if (!(this.g == this.h)) {
                r.c("endGroup() not called at the end of a group");
            }
            int i = (this.i * 5) + 2;
            int[] iArr = this.b;
            int i2 = iArr[i];
            this.i = i2;
            int i3 = this.c;
            this.h = i2 < 0 ? i3 : C0.a(iArr, i2) + i2;
            int iB = this.j.b();
            if (iB < 0) {
                this.l = 0;
                this.m = 0;
            } else {
                this.l = iB;
                this.m = i2 >= i3 - 1 ? this.e : iArr[((i2 + 1) * 5) + 4];
            }
        }
    }

    public final Object f() {
        int i = this.g;
        if (i < this.h) {
            return b(this.b, i);
        }
        return 0;
    }

    public final int g() {
        int i = this.g;
        if (i >= this.h) {
            return 0;
        }
        return this.b[i * 5];
    }

    public final Object h(int i, int i2) {
        int[] iArr = this.b;
        int iC = C0.c(iArr, i);
        int i3 = i + 1;
        int i4 = iC + i2;
        return i4 < (i3 < this.c ? iArr[(i3 * 5) + 4] : this.e) ? this.d[i4] : C0804k.a;
    }

    public final boolean i(int i) {
        return (this.b[(i * 5) + 1] & 536870912) != 0;
    }

    public final boolean j(int i) {
        return (this.b[(i * 5) + 1] & 1073741824) != 0;
    }

    public final Object k() {
        int i;
        if (this.k > 0 || (i = this.l) >= this.m) {
            this.n = false;
            return C0804k.a;
        }
        this.n = true;
        this.l = i + 1;
        return this.d[i];
    }

    public final Object l(int i) {
        int i2 = i * 5;
        int[] iArr = this.b;
        int i3 = iArr[i2 + 1] & 1073741824;
        if (i3 == 0) {
            return null;
        }
        if (i3 == 0) {
            return C0804k.a;
        }
        return this.d[iArr[i2 + 4]];
    }

    public final int m(int i) {
        return this.b[(i * 5) + 1] & 67108863;
    }

    public final Object n(int[] iArr, int i) {
        int i2 = i * 5;
        int i3 = iArr[i2 + 1];
        if ((536870912 & i3) == 0) {
            return null;
        }
        return this.d[Integer.bitCount(i3 >> 30) + iArr[i2 + 4]];
    }

    public final int o(int i) {
        return this.b[(i * 5) + 2];
    }

    public final void p(int i) {
        if (!(this.k == 0)) {
            r.c("Cannot reposition while in an empty region");
        }
        this.g = i;
        int[] iArr = this.b;
        int i2 = this.c;
        int i3 = i < i2 ? iArr[(i * 5) + 2] : -1;
        this.i = i3;
        if (i3 < 0) {
            this.h = i2;
        } else {
            this.h = C0.a(iArr, i3) + i3;
        }
        this.l = 0;
        this.m = 0;
    }

    public final int q() {
        if (!(this.k == 0)) {
            r.c("Cannot skip while in an empty region");
        }
        int i = this.g;
        int[] iArr = this.b;
        int i2 = (iArr[(i * 5) + 1] & 1073741824) == 0 ? iArr[(i * 5) + 1] & 67108863 : 1;
        this.g = C0.a(iArr, i) + i;
        return i2;
    }

    public final void r() {
        if (!(this.k == 0)) {
            r.c("Cannot skip the enclosing group while in an empty region");
        }
        this.g = this.h;
        this.l = 0;
        this.m = 0;
    }

    public final void s() {
        if (this.k <= 0) {
            int i = this.i;
            int i2 = this.g;
            int[] iArr = this.b;
            if (!(iArr[(i2 * 5) + 2] == i)) {
                AbstractC0805k0.a("Invalid slot table detected");
            }
            int i3 = this.l;
            int i4 = this.m;
            N n = this.j;
            if (i3 == 0 && i4 == 0) {
                n.c(-1);
            } else {
                n.c(i3);
            }
            this.i = i2;
            this.h = C0.a(iArr, i2) + i2;
            int i5 = i2 + 1;
            this.g = i5;
            this.l = C0.c(iArr, i2);
            this.m = i2 >= this.c - 1 ? this.e : iArr[(i5 * 5) + 4];
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SlotReader(current=");
        sb.append(this.g);
        sb.append(", key=");
        sb.append(g());
        sb.append(", parent=");
        sb.append(this.i);
        sb.append(", end=");
        return android.support.v4.media.session.a.q(sb, this.h, ')');
    }
}
