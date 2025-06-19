package androidx.compose.material3;

import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.comscore.streaming.ContentType;

/* renamed from: androidx.compose.material3.o3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0696o3 {
    public static final androidx.compose.runtime.X0 a = new androidx.compose.runtime.X0(C0584a0.p);
    public static final androidx.compose.runtime.B b = new androidx.compose.runtime.B(C0584a0.o);
    public static final C0702p3 c;
    public static final C0702p3 d;

    static {
        long j = C0861v.g;
        c = new C0702p3(true, Float.NaN, j);
        d = new C0702p3(false, Float.NaN, j);
    }

    public static final C0702p3 a(boolean z, float f, long j) {
        return (androidx.compose.ui.unit.e.a(f, Float.NaN) && C0861v.c(j, C0861v.g)) ? z ? c : d : new C0702p3(z, f, j);
    }

    public static C0702p3 b(boolean z) {
        return a(z, Float.NaN, C0861v.g);
    }

    public static final InterfaceC0369j0 c(boolean z, float f, long j, InterfaceC0806l interfaceC0806l, int i, int i2) {
        InterfaceC0369j0 interfaceC0369j0A;
        boolean z2 = true;
        if ((i2 & 1) != 0) {
            z = true;
        }
        if ((i2 & 2) != 0) {
            f = Float.NaN;
        }
        if ((i2 & 4) != 0) {
            j = C0861v.g;
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1280632857);
        if (((Boolean) c0814p.j(a)).booleanValue()) {
            androidx.compose.animation.core.K0 k0 = androidx.compose.material.ripple.k.a;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(new C0861v(j), c0814p);
            boolean z3 = (((i & 14) ^ 6) > 4 && c0814p.g(z)) || (i & 6) == 4;
            if ((((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) <= 32 || !c0814p.c(f)) && (i & 48) != 32) {
                z2 = false;
            }
            boolean z4 = z3 | z2;
            Object objI = c0814p.I();
            if (z4 || objI == C0804k.a) {
                objI = new androidx.compose.material.ripple.d(z, f, interfaceC0773a0D);
                c0814p.i0(objI);
            }
            interfaceC0369j0A = (androidx.compose.material.ripple.d) objI;
        } else {
            interfaceC0369j0A = a(z, f, j);
        }
        c0814p.p(false);
        return interfaceC0369j0A;
    }
}
