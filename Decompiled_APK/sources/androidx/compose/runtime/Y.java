package androidx.compose.runtime;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y {
    public final A0 a;

    public Y(A0 a0) {
        this.a = a0;
    }

    public static final void a(D0 d0, int i) {
        while (d0.v >= 0 && d0.u <= i) {
            d0.L();
            d0.i();
        }
    }

    public final androidx.collection.I b(InterfaceC0790d interfaceC0790d, androidx.collection.G g) {
        A0 a0;
        int i;
        Object[] objArr = g.a;
        int i2 = g.b;
        int i3 = 0;
        while (true) {
            a0 = this.a;
            if (i3 >= i2) {
                break;
            }
            if (a0.h(((Z) objArr[i3]).e)) {
                i3++;
            } else {
                androidx.collection.G g2 = new androidx.collection.G();
                Object[] objArr2 = g.a;
                int i4 = g.b;
                for (int i5 = 0; i5 < i4; i5++) {
                    Object obj = objArr2[i5];
                    if (a0.h(((Z) obj).e)) {
                        g2.a(obj);
                    }
                }
                g = g2;
            }
        }
        androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(this, 29);
        if (g.b > 1) {
            Comparable comparable = (Comparable) fVar.invoke(g.c(0));
            int i6 = g.b;
            int i7 = 1;
            while (true) {
                if (i7 >= i6) {
                    break;
                }
                Comparable comparable2 = (Comparable) fVar.invoke(g.c(i7));
                if (comparable.compareTo(comparable2) > 0) {
                    androidx.collection.G g3 = new androidx.collection.G(g.b);
                    Object[] objArr3 = g.a;
                    int i8 = g.b;
                    for (int i9 = 0; i9 < i8; i9++) {
                        g3.a(objArr3[i9]);
                    }
                    androidx.collection.E e = g3.c;
                    if (e == null) {
                        e = new androidx.collection.E(g3);
                        g3.c = e;
                    }
                    if (((androidx.collection.G) e.b).b > 1) {
                        kotlin.collections.F.t(e, new androidx.camera.core.streamsharing.a(fVar, 2));
                    }
                    g = g3;
                } else {
                    i7++;
                    comparable = comparable2;
                }
            }
        }
        if (g.e()) {
            androidx.collection.I i10 = androidx.collection.S.b;
            Intrinsics.e(i10, "null cannot be cast to non-null type androidx.collection.ScatterMap<K of androidx.collection.ScatterMapKt.emptyScatterMap, V of androidx.collection.ScatterMapKt.emptyScatterMap>");
            return i10;
        }
        long[] jArr = androidx.collection.S.a;
        androidx.collection.I i11 = new androidx.collection.I();
        D0 d0G = a0.g();
        try {
            Object[] objArr4 = g.a;
            int i12 = g.b;
            for (int i13 = 0; i13 < i12; i13++) {
                Z z = (Z) objArr4[i13];
                int iC = d0G.c(z.e);
                int iE = d0G.E(d0G.b, iC);
                a(d0G, iE);
                a(d0G, iE);
                while (true) {
                    i = d0G.t;
                    if (i == iE || i == d0G.u) {
                        break;
                    }
                    if (iE < d0G.s(i) + i) {
                        d0G.P();
                    } else {
                        d0G.K();
                    }
                }
                if (i != iE) {
                    r.c("Unexpected slot table structure");
                }
                d0G.P();
                d0G.a(iC - d0G.t);
                i11.j(z, r.f(z.c, z, d0G, interfaceC0790d));
            }
            a(d0G, SubsamplingScaleImageView.TILE_SIZE_AUTO);
            Unit unit = Unit.a;
            d0G.e(true);
            return i11;
        } catch (Throwable th) {
            d0G.e(false);
            throw th;
        }
    }
}
