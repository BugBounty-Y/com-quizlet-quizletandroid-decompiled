package androidx.compose.material3;

import androidx.compose.foundation.AbstractC0455m0;
import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class R1 {
    static {
        new androidx.compose.runtime.U(C0584a0.m);
    }

    public static final void a(Z z, A3 a3, Y4 y4, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        A3 a32;
        A3 a33;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2127166334);
        if (((i | (c0814p.f(z) ? 4 : 2) | 16 | (c0814p.h(dVar) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            a33 = a3;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                a32 = (A3) c0814p.j(B3.a);
            } else {
                c0814p.Q();
                a32 = a3;
            }
            c0814p.q();
            InterfaceC0369j0 interfaceC0369j0C = AbstractC0696o3.c(false, DefinitionKt.NO_Float_VALUE, 0L, c0814p, 0, 7);
            long j = z.a;
            boolean zE = c0814p.e(j);
            Object objI = c0814p.I();
            if (zE || objI == C0804k.a) {
                objI = new androidx.compose.foundation.text.selection.p0(j, C0861v.b(j, 0.4f));
                c0814p.i0(objI);
            }
            C0776c.b(new C0811n0[]{AbstractC0590b0.a.a(z), AbstractC0455m0.a.a(interfaceC0369j0C), androidx.compose.material.ripple.o.a.a(C0596c0.a), B3.a.a(a32), androidx.compose.foundation.text.selection.q0.a.a((androidx.compose.foundation.text.selection.p0) objI), Z4.a.a(y4)}, androidx.compose.runtime.internal.e.e(-1066563262, new androidx.compose.foundation.contextmenu.i(16, y4, dVar), c0814p), c0814p, 56);
            a33 = a32;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.N(z, a33, y4, dVar, i);
        }
    }
}
