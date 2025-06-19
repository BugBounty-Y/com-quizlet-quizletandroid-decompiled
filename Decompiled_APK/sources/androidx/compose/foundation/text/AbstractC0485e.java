package androidx.compose.foundation.text;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.text.selection.InterfaceC0533n;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0485e {
    public static final float a;
    public static final float b;

    static {
        float f = 25;
        a = f;
        b = (f * 2.0f) / 2.4142137f;
    }

    public static final void a(InterfaceC0533n interfaceC0533n, androidx.compose.ui.q qVar, long j, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1776202187);
        int i3 = (c0814p.f(interfaceC0533n) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                i2 = i3 & (-897);
                j = 9205357640488583168L;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
            }
            c0814p.q();
            int i4 = i2 & 14;
            boolean z = i4 == 4;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new androidx.camera.lifecycle.f(interfaceC0533n, 20);
                c0814p.i0(objI);
            }
            androidx.compose.foundation.text.selection.W.a(interfaceC0533n, androidx.compose.ui.b.b, androidx.compose.runtime.internal.e.e(-1653527038, new androidx.compose.material3.internal.Q(j, androidx.compose.ui.semantics.m.a(qVar, false, (Function1) objI), 2), c0814p), c0814p, i4 | 432);
        }
        long j2 = j;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0477a(interfaceC0533n, qVar, j2, i);
        }
    }

    public static final void b(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(694251107);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else if ((i & 6) == 0) {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                qVar = androidx.compose.ui.n.b;
            }
            AbstractC0382e.f(c0814p, androidx.compose.ui.a.a(androidx.compose.foundation.layout.K0.l(qVar, b, a), C0483d.a));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0479b(i, i2, qVar);
        }
    }
}
