package androidx.compose.animation.core;

import androidx.compose.animation.C0281h;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N {
    public final androidx.compose.runtime.collection.b a = new androidx.compose.runtime.collection.b(new J[16]);
    public final InterfaceC0773a0 b = C0776c.z(Boolean.FALSE);
    public long c = Long.MIN_VALUE;
    public final InterfaceC0773a0 d = C0776c.z(Boolean.TRUE);

    public final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-318043801);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(null);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            if (((Boolean) ((androidx.compose.runtime.L0) this.d).getValue()).booleanValue() || ((Boolean) ((androidx.compose.runtime.L0) this.b).getValue()).booleanValue()) {
                c0814p.X(1719915818);
                boolean zH = c0814p.h(this);
                Object objI2 = c0814p.I();
                if (zH || objI2 == v) {
                    objI2 = new M(interfaceC0773a0, this, null);
                    c0814p.i0(objI2);
                }
                C0776c.f(c0814p, this, (Function2) objI2);
                c0814p.p(false);
            } else {
                c0814p.X(1721436120);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0281h(this, i, 1);
        }
    }
}
