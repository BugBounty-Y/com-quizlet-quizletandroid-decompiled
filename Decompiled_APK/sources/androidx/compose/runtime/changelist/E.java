package androidx.compose.runtime.changelist;

import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0836x0;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;

/* loaded from: classes.dex */
public final class E extends J {
    public static final E c = new E(1, 0, 2);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        int iC;
        int iO;
        int iE = k.e(0);
        int iO2 = d0.o();
        int i = d0.v;
        int iM = d0.M(d0.b, d0.q(i));
        int iF = d0.f(d0.b, d0.q(i + 1));
        for (int iMax = Math.max(iM, iF - iE); iMax < iF; iMax++) {
            Object obj = d0.c[d0.g(iMax)];
            if (obj instanceof C0836x0) {
                int i2 = iO2 - iMax;
                C0836x0 c0836x0 = (C0836x0) obj;
                C0774b c0774b = c0836x0.b;
                if (c0774b == null || !c0774b.a()) {
                    iC = -1;
                    iO = -1;
                } else {
                    iC = d0.c(c0774b);
                    iO = d0.o() - d0.O(iC);
                }
                jVar.w(c0836x0, i2, iC, iO);
            } else if (obj instanceof C0813o0) {
                ((C0813o0) obj).d();
            }
        }
        if (!(iE > 0)) {
            androidx.compose.runtime.r.c("Check failed");
        }
        int i3 = d0.v;
        int iM2 = d0.M(d0.b, d0.q(i3));
        int iF2 = d0.f(d0.b, d0.q(i3 + 1)) - iE;
        if (iF2 < iM2) {
            androidx.compose.runtime.r.c("Check failed");
        }
        d0.J(iF2, iE, i3);
        int i4 = d0.i;
        if (i4 >= iM2) {
            d0.i = i4 - iE;
        }
    }
}
