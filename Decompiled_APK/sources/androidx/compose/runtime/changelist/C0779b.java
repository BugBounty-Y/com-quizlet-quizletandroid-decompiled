package androidx.compose.runtime.changelist;

import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0840z0;
import androidx.compose.runtime.N;
import androidx.compose.runtime.Y;
import androidx.compose.runtime.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.D4;
import java.util.ArrayList;

/* renamed from: androidx.compose.runtime.changelist.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0779b {
    public final C0814p a;
    public C0778a b;
    public boolean c;
    public int f;
    public int g;
    public int l;
    public final N d = new N();
    public boolean e = true;
    public final ArrayList h = new ArrayList();
    public int i = -1;
    public int j = -1;
    public int k = -1;

    public C0779b(C0814p c0814p, C0778a c0778a) {
        this.a = c0814p;
        this.b = c0778a;
    }

    public final void a(Y y, AbstractC0827t abstractC0827t, Z z, Z z2) {
        C0778a c0778a = this.b;
        c0778a.getClass();
        C0785h c0785h = C0785h.c;
        L l = c0778a.b;
        l.f(c0785h);
        int i = l.g - l.b[l.c - 1].b;
        Object[] objArr = l.f;
        objArr[i] = y;
        objArr[i + 1] = abstractC0827t;
        objArr[i + 3] = z2;
        objArr[i + 2] = z;
    }

    public final void b() {
        d();
        ArrayList arrayList = this.h;
        if (arrayList.isEmpty()) {
            this.g++;
        } else {
            arrayList.remove(arrayList.size() - 1);
        }
    }

    public final void c() {
        int i = this.g;
        if (i > 0) {
            C0778a c0778a = this.b;
            c0778a.getClass();
            H h = H.c;
            L l = c0778a.b;
            l.f(h);
            l.d[l.e - l.b[l.c - 1].a] = i;
            this.g = 0;
        }
        ArrayList arrayList = this.h;
        if (arrayList.isEmpty()) {
            return;
        }
        C0778a c0778a2 = this.b;
        int size = arrayList.size();
        Object[] objArr = new Object[size];
        for (int i2 = 0; i2 < size; i2++) {
            objArr[i2] = arrayList.get(i2);
        }
        c0778a2.getClass();
        if (size != 0) {
            C0788k c0788k = C0788k.c;
            L l2 = c0778a2.b;
            l2.f(c0788k);
            D4.b(l2, 0, objArr);
        }
        arrayList.clear();
    }

    public final void d() {
        int i = this.l;
        if (i > 0) {
            int i2 = this.i;
            if (i2 >= 0) {
                c();
                C0778a c0778a = this.b;
                c0778a.getClass();
                z zVar = z.c;
                L l = c0778a.b;
                l.f(zVar);
                int i3 = l.e - l.b[l.c - 1].a;
                int[] iArr = l.d;
                iArr[i3] = i2;
                iArr[i3 + 1] = i;
                this.i = -1;
            } else {
                int i4 = this.k;
                int i5 = this.j;
                c();
                C0778a c0778a2 = this.b;
                c0778a2.getClass();
                v vVar = v.c;
                L l2 = c0778a2.b;
                l2.f(vVar);
                int i6 = l2.e - l2.b[l2.c - 1].a;
                int[] iArr2 = l2.d;
                iArr2[i6 + 1] = i4;
                iArr2[i6] = i5;
                iArr2[i6 + 2] = i;
                this.j = -1;
                this.k = -1;
            }
            this.l = 0;
        }
    }

    public final void e(boolean z) {
        C0814p c0814p = this.a;
        int i = z ? c0814p.F.i : c0814p.F.g;
        int i2 = i - this.f;
        if (i2 < 0) {
            androidx.compose.runtime.r.c("Tried to seek backward");
        }
        if (i2 > 0) {
            C0778a c0778a = this.b;
            c0778a.getClass();
            C0781d c0781d = C0781d.c;
            L l = c0778a.b;
            l.f(c0781d);
            l.d[l.e - l.b[l.c - 1].a] = i2;
            this.f = i;
        }
    }

    public final void f() {
        C0840z0 c0840z0 = this.a.F;
        if (c0840z0.c > 0) {
            int i = c0840z0.i;
            N n = this.d;
            if (n.a(-2) != i) {
                if (!this.c && this.e) {
                    e(false);
                    C0778a c0778a = this.b;
                    c0778a.getClass();
                    c0778a.b.f(q.c);
                    this.c = true;
                }
                if (i > 0) {
                    C0774b c0774bA = c0840z0.a(i);
                    n.c(i);
                    e(false);
                    C0778a c0778a2 = this.b;
                    c0778a2.getClass();
                    p pVar = p.c;
                    L l = c0778a2.b;
                    l.f(pVar);
                    D4.b(l, 0, c0774bA);
                    this.c = true;
                }
            }
        }
    }

    public final void g(int i, int i2) {
        if (i2 > 0) {
            if (!(i >= 0)) {
                androidx.compose.runtime.r.c("Invalid remove index " + i);
            }
            if (this.i == i) {
                this.l += i2;
                return;
            }
            d();
            this.i = i;
            this.l = i2;
        }
    }
}
