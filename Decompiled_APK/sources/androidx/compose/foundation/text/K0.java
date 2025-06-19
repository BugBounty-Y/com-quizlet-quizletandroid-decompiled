package androidx.compose.foundation.text;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public final class K0 {
    public final androidx.compose.ui.text.H a;
    public androidx.compose.ui.layout.r b = null;
    public androidx.compose.ui.layout.r c;

    public K0(androidx.compose.ui.layout.r rVar, androidx.compose.ui.text.H h) {
        this.a = h;
        this.c = rVar;
    }

    public final long a(long j) {
        androidx.compose.ui.geometry.c cVarO;
        androidx.compose.ui.layout.r rVar = this.b;
        androidx.compose.ui.geometry.c cVar = androidx.compose.ui.geometry.c.e;
        if (rVar != null) {
            if (rVar.k()) {
                androidx.compose.ui.layout.r rVar2 = this.c;
                cVarO = rVar2 != null ? rVar2.o(rVar, true) : null;
            } else {
                cVarO = cVar;
            }
            if (cVarO != null) {
                cVar = cVarO;
            }
        }
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fD2 = cVar.a;
        if (fD >= fD2) {
            float fD3 = androidx.compose.ui.geometry.b.d(j);
            fD2 = cVar.c;
            if (fD3 <= fD2) {
                fD2 = androidx.compose.ui.geometry.b.d(j);
            }
        }
        float fE = androidx.compose.ui.geometry.b.e(j);
        float fE2 = cVar.b;
        if (fE >= fE2) {
            float fE3 = androidx.compose.ui.geometry.b.e(j);
            fE2 = cVar.d;
            if (fE3 <= fE2) {
                fE2 = androidx.compose.ui.geometry.b.e(j);
            }
        }
        return Q4.c(fD2, fE2);
    }

    public final int b(long j, boolean z) {
        if (z) {
            j = a(j);
        }
        return this.a.b.e(d(j));
    }

    public final boolean c(long j) {
        long jD = d(a(j));
        float fE = androidx.compose.ui.geometry.b.e(jD);
        androidx.compose.ui.text.H h = this.a;
        int iC = h.b.c(fE);
        return androidx.compose.ui.geometry.b.d(jD) >= h.g(iC) && androidx.compose.ui.geometry.b.d(jD) <= h.h(iC);
    }

    public final long d(long j) {
        androidx.compose.ui.layout.r rVar;
        androidx.compose.ui.layout.r rVar2 = this.b;
        if (rVar2 == null) {
            return j;
        }
        if (!rVar2.k()) {
            rVar2 = null;
        }
        if (rVar2 == null || (rVar = this.c) == null) {
            return j;
        }
        androidx.compose.ui.layout.r rVar3 = rVar.k() ? rVar : null;
        return rVar3 == null ? j : rVar2.f(rVar3, j);
    }

    public final long e(long j) {
        androidx.compose.ui.layout.r rVar;
        androidx.compose.ui.layout.r rVar2 = this.b;
        if (rVar2 == null) {
            return j;
        }
        if (!rVar2.k()) {
            rVar2 = null;
        }
        if (rVar2 == null || (rVar = this.c) == null) {
            return j;
        }
        androidx.compose.ui.layout.r rVar3 = rVar.k() ? rVar : null;
        return rVar3 == null ? j : rVar3.f(rVar2, j);
    }
}
