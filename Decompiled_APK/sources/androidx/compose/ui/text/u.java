package androidx.compose.ui.text;

import com.google.android.gms.internal.mlkit_vision_barcode.S5;

/* loaded from: classes.dex */
public abstract class u {
    public static final long a;
    public static final /* synthetic */ int b = 0;

    static {
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        a = androidx.compose.ui.unit.m.c;
    }

    public static final t a(t tVar, int i, int i2, long j, androidx.compose.ui.text.style.p pVar, w wVar, androidx.compose.ui.text.style.g gVar, int i3, int i4, androidx.compose.ui.text.style.q qVar) {
        long j2;
        androidx.compose.ui.text.style.p pVar2 = pVar;
        w wVar2 = wVar;
        androidx.compose.ui.text.style.g gVar2 = gVar;
        int i5 = i3;
        int i6 = i4;
        if (i == Integer.MIN_VALUE || i == tVar.a) {
            if (S5.h(j)) {
                j2 = j;
            } else {
                j2 = j;
                if (androidx.compose.ui.unit.m.a(j2, tVar.c)) {
                }
            }
            if ((pVar2 == null || pVar2.equals(tVar.d)) && ((i2 == Integer.MIN_VALUE || i2 == tVar.b) && ((wVar2 == null || wVar2.equals(tVar.e)) && ((gVar2 == null || gVar2.equals(tVar.f)) && ((i5 == 0 || i5 == tVar.g) && ((i6 == Integer.MIN_VALUE || i6 == tVar.h) && (qVar == null || qVar.equals(tVar.i)))))))) {
                return tVar;
            }
        } else {
            j2 = j;
        }
        long j3 = S5.h(j2) ? tVar.c : j2;
        if (pVar2 == null) {
            pVar2 = tVar.d;
        }
        if (i == Integer.MIN_VALUE) {
            i = tVar.a;
        }
        int i7 = i2 == Integer.MIN_VALUE ? tVar.b : i2;
        w wVar3 = tVar.e;
        if (wVar3 != null && wVar2 == null) {
            wVar2 = wVar3;
        }
        if (gVar2 == null) {
            gVar2 = tVar.f;
        }
        if (i5 == 0) {
            i5 = tVar.g;
        }
        if (i6 == Integer.MIN_VALUE) {
            i6 = tVar.h;
        }
        return new t(i, i7, j3, pVar2, wVar2, gVar2, i5, i6, qVar == null ? tVar.i : qVar);
    }
}
