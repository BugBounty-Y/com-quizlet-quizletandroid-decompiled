package androidx.compose.foundation.lazy.layout;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H {
    public androidx.compose.ui.unit.a b;
    public int c;
    public int d;
    public int f;
    public int g;
    public final /* synthetic */ K h;
    public E[] a = AbstractC0448u.a;
    public int e = 1;

    public H(K k) {
        this.h = k;
    }

    public static void b(H h, V v, kotlinx.coroutines.C c, androidx.compose.ui.graphics.E e, int i, int i2) {
        h.h.getClass();
        long jI = v.i(0);
        h.a(v, c, e, i, i2, (int) (!v.g() ? jI & 4294967295L : jI >> 32));
    }

    public final void a(V v, kotlinx.coroutines.C c, androidx.compose.ui.graphics.E e, int i, int i2, int i3) {
        E[] eArr = this.a;
        int length = eArr.length;
        int i4 = 0;
        while (true) {
            if (i4 >= length) {
                this.f = i;
                this.g = i2;
                break;
            } else {
                E e2 = eArr[i4];
                if (e2 != null && e2.g) {
                    break;
                } else {
                    i4++;
                }
            }
        }
        int length2 = this.a.length;
        for (int iA = v.a(); iA < length2; iA++) {
            E e3 = this.a[iA];
            if (e3 != null) {
                e3.c();
            }
        }
        if (this.a.length != v.a()) {
            Object[] objArrCopyOf = Arrays.copyOf(this.a, v.a());
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(this, newSize)");
            this.a = (E[]) objArrCopyOf;
        }
        this.b = new androidx.compose.ui.unit.a(v.f());
        this.c = i3;
        this.d = v.j();
        this.e = v.d();
        int iA2 = v.a();
        for (int i5 = 0; i5 < iA2; i5++) {
            Object objE = v.e(i5);
            C0441m c0441m = objE instanceof C0441m ? (C0441m) objE : null;
            if (c0441m == null) {
                E e4 = this.a[i5];
                if (e4 != null) {
                    e4.c();
                }
                this.a[i5] = null;
            } else {
                E e5 = this.a[i5];
                if (e5 == null) {
                    e5 = new E(c, e, new androidx.compose.animation.core.K(this.h, 6));
                    this.a[i5] = e5;
                }
                e5.d = c0441m.n;
                e5.e = c0441m.o;
                e5.f = c0441m.p;
            }
        }
    }
}
