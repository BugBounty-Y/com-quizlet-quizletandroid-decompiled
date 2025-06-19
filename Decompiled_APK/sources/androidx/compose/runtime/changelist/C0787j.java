package androidx.compose.runtime.changelist;

import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import com.google.android.gms.internal.mlkit_vision_barcode.C4;

/* renamed from: androidx.compose.runtime.changelist.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0787j extends J {
    public static final C0787j c = new C0787j(0, 2, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        int i;
        androidx.compose.runtime.internal.f fVar = (androidx.compose.runtime.internal.f) k.f(0);
        int iC = d0.c((C0774b) k.f(1));
        if (!(d0.t < iC)) {
            androidx.compose.runtime.r.c("Check failed");
        }
        C4.b(d0, interfaceC0790d, iC);
        int i2 = d0.t;
        int iE = d0.v;
        while (iE >= 0 && !d0.w(iE)) {
            iE = d0.E(d0.b, iE);
        }
        int iS = iE + 1;
        int iK = 0;
        while (iS < i2) {
            if (d0.t(i2, iS)) {
                if (d0.w(iS)) {
                    iK = 0;
                }
                iS++;
            } else {
                iK += d0.w(iS) ? 1 : d0.D(iS);
                iS += d0.s(iS);
            }
        }
        while (true) {
            i = d0.t;
            if (i >= iC) {
                break;
            }
            if (d0.t(iC, i)) {
                int i3 = d0.t;
                if (i3 < d0.u && (d0.b[(d0.q(i3) * 5) + 1] & 1073741824) != 0) {
                    interfaceC0790d.d(d0.C(d0.t));
                    iK = 0;
                }
                d0.P();
            } else {
                iK += d0.K();
            }
        }
        if (i != iC) {
            androidx.compose.runtime.r.c("Check failed");
        }
        fVar.a = iK;
    }
}
