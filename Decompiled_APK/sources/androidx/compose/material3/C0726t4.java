package androidx.compose.material3;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;

/* renamed from: androidx.compose.material3.t4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0726t4 {
    public static final C0726t4 a = new C0726t4();

    public final void a(androidx.compose.ui.q qVar, float f, long j, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1454716052);
        if ((((c0814p.f(qVar) ? 4 : 2) | i | (c0814p.c(f) ? 32 : 16) | (c0814p.e(j) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            AbstractC0409s.a(AbstractC0460p.f(androidx.compose.foundation.layout.K0.d(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), f), j, androidx.compose.ui.graphics.F.a), c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0720s4(this, qVar, f, j, i);
        }
    }
}
