package androidx.compose.runtime.changelist;

import androidx.compose.runtime.C0;
import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import java.util.ArrayList;
import kotlin.collections.C4930v;

/* loaded from: classes.dex */
public final class u extends J {
    public static final u c = new u(1, 0, 2);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        C0774b c0774b;
        int iC;
        int iE = k.e(0);
        if (d0.n != 0) {
            androidx.compose.runtime.r.c("Cannot move a group while inserting");
        }
        boolean z = true;
        if (!(iE >= 0)) {
            androidx.compose.runtime.r.c("Parameter offset is out of bounds");
        }
        if (iE == 0) {
            return;
        }
        int i = d0.t;
        int i2 = d0.v;
        int i3 = d0.u;
        int i4 = i;
        while (iE > 0) {
            i4 += d0.b[(d0.q(i4) * 5) + 3];
            if (i4 > i3) {
                androidx.compose.runtime.r.c("Parameter offset is out of bounds");
            }
            iE--;
        }
        int i5 = d0.b[(d0.q(i4) * 5) + 3];
        int iF = d0.f(d0.b, d0.q(d0.t));
        int iF2 = d0.f(d0.b, d0.q(i4));
        int i6 = i4 + i5;
        int iF3 = d0.f(d0.b, d0.q(i6));
        int i7 = iF3 - iF2;
        d0.v(i7, Math.max(d0.t - 1, 0));
        d0.u(i5);
        int[] iArr = d0.b;
        int iQ = d0.q(i6) * 5;
        C4930v.e(d0.q(i) * 5, iQ, (i5 * 5) + iQ, iArr, iArr);
        if (i7 > 0) {
            Object[] objArr = d0.c;
            int iG = d0.g(iF2 + i7);
            System.arraycopy(objArr, iG, objArr, iF, d0.g(iF3 + i7) - iG);
        }
        int i8 = iF2 + i7;
        int i9 = i8 - iF;
        int i10 = d0.k;
        int i11 = d0.l;
        int length = d0.c.length;
        int i12 = d0.m;
        int i13 = i + i5;
        int i14 = i;
        while (i14 < i13) {
            boolean z2 = z;
            int iQ2 = d0.q(i14);
            int i15 = i14;
            iArr[(iQ2 * 5) + 4] = D0.h(D0.h(d0.f(iArr, iQ2) - i9, i12 < iQ2 ? 0 : i10, i11, length), d0.k, d0.l, d0.c.length);
            i14 = i15 + 1;
            z = z2;
            i9 = i9;
            i10 = i10;
        }
        int i16 = i6 + i5;
        int iN = d0.n();
        int iB = C0.b(d0.d, i6, iN);
        ArrayList arrayList = new ArrayList();
        if (iB >= 0) {
            while (iB < d0.d.size() && (iC = d0.c((c0774b = (C0774b) d0.d.get(iB)))) >= i6 && iC < i16) {
                arrayList.add(c0774b);
                d0.d.remove(iB);
            }
        }
        int i17 = i - i6;
        int size = arrayList.size();
        for (int i18 = 0; i18 < size; i18++) {
            C0774b c0774b2 = (C0774b) arrayList.get(i18);
            int iC2 = d0.c(c0774b2) + i17;
            if (iC2 >= d0.g) {
                c0774b2.a = -(iN - iC2);
            } else {
                c0774b2.a = iC2;
            }
            d0.d.add(C0.b(d0.d, iC2, iN), c0774b2);
        }
        if (d0.I(i6, i5)) {
            androidx.compose.runtime.r.c("Unexpectedly removed anchors");
        }
        d0.l(i2, d0.u, i);
        if (i7 > 0) {
            d0.J(i8, i7, i6 - 1);
        }
    }
}
