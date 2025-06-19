package androidx.compose.foundation.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0415v implements androidx.compose.ui.layout.K {
    public final androidx.compose.ui.d a;
    public final boolean b;

    public C0415v(androidx.compose.ui.d dVar, boolean z) {
        this.a = dVar;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0415v)) {
            return false;
        }
        C0415v c0415v = (C0415v) obj;
        return Intrinsics.b(this.a, c0415v.a) && this.b == c0415v.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        int iJ;
        int i;
        androidx.compose.ui.layout.W wB;
        if (list.isEmpty()) {
            return m.n0(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.i(j), kotlin.collections.V.c(), C0406q.c);
        }
        long jA = this.b ? j : androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        if (list.size() == 1) {
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) list.get(0);
            Object objG = j2.G();
            C0402o c0402o = objG instanceof C0402o ? (C0402o) objG : null;
            if (c0402o != null ? c0402o.o : false) {
                iJ = androidx.compose.ui.unit.a.j(j);
                i = androidx.compose.ui.unit.a.i(j);
                int iJ2 = androidx.compose.ui.unit.a.j(j);
                int i2 = androidx.compose.ui.unit.a.i(j);
                if (!(iJ2 >= 0 && i2 >= 0)) {
                    O5.e("width(" + iJ2 + ") and height(" + i2 + ") must be >= 0");
                    throw null;
                }
                wB = j2.B(L5.m(iJ2, iJ2, i2, i2));
            } else {
                wB = j2.B(jA);
                iJ = Math.max(androidx.compose.ui.unit.a.j(j), wB.a);
                i = Math.max(androidx.compose.ui.unit.a.i(j), wB.b);
            }
            int i3 = i;
            int i4 = iJ;
            return m.n0(i4, i3, kotlin.collections.V.c(), new C0411t(wB, j2, m, i4, i3, this));
        }
        androidx.compose.ui.layout.W[] wArr = new androidx.compose.ui.layout.W[list.size()];
        kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
        h.a = androidx.compose.ui.unit.a.j(j);
        kotlin.jvm.internal.H h2 = new kotlin.jvm.internal.H();
        h2.a = androidx.compose.ui.unit.a.i(j);
        int size = list.size();
        boolean z = false;
        for (int i5 = 0; i5 < size; i5++) {
            androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) list.get(i5);
            Object objG2 = j3.G();
            C0402o c0402o2 = objG2 instanceof C0402o ? (C0402o) objG2 : null;
            if (c0402o2 != null ? c0402o2.o : false) {
                z = true;
            } else {
                androidx.compose.ui.layout.W wB2 = j3.B(jA);
                wArr[i5] = wB2;
                h.a = Math.max(h.a, wB2.a);
                h2.a = Math.max(h2.a, wB2.b);
            }
        }
        if (z) {
            int i6 = h.a;
            int i7 = i6 != Integer.MAX_VALUE ? i6 : 0;
            int i8 = h2.a;
            long jA2 = L5.a(i7, i6, i8 != Integer.MAX_VALUE ? i8 : 0, i8);
            int size2 = list.size();
            for (int i9 = 0; i9 < size2; i9++) {
                androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) list.get(i9);
                Object objG3 = j4.G();
                C0402o c0402o3 = objG3 instanceof C0402o ? (C0402o) objG3 : null;
                if (c0402o3 != null ? c0402o3.o : false) {
                    wArr[i9] = j4.B(jA2);
                }
            }
        }
        return m.n0(h.a, h2.a, kotlin.collections.V.c(), new C0413u(wArr, list, m, h, h2, this, 0));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BoxMeasurePolicy(alignment=");
        sb.append(this.a);
        sb.append(", propagateMinConstraints=");
        return android.support.v4.media.session.a.u(sb, this.b, ')');
    }
}
