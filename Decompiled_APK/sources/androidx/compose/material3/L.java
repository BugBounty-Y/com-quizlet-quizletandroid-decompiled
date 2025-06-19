package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public abstract class L {
    public static final androidx.compose.foundation.layout.A0 a;
    public static final androidx.compose.foundation.layout.A0 b;
    public static final float c;
    public static final float d;
    public static final float e;

    static {
        float f = 24;
        float f2 = 8;
        a = new androidx.compose.foundation.layout.A0(f, f2, f, f2);
        float f3 = 16;
        AbstractC0382e.d(f3, f2, f, f2);
        float f4 = 12;
        b = new androidx.compose.foundation.layout.A0(f4, f2, f4, f2);
        AbstractC0382e.d(f4, f2, f3, f2);
        c = 58;
        d = 40;
        float f5 = androidx.compose.material3.tokens.k.a;
        e = f2;
    }

    public static K a(long j, long j2, long j3, long j4, InterfaceC0806l interfaceC0806l, int i) {
        if ((i & 2) != 0) {
            j2 = C0861v.g;
        }
        return b((Z) ((C0814p) interfaceC0806l).j(AbstractC0590b0.a)).a(j, j2, j3, j4);
    }

    public static K b(Z z) {
        K k = z.K;
        if (k != null) {
            return k;
        }
        float f = androidx.compose.material3.tokens.k.a;
        K k2 = new K(AbstractC0590b0.c(z, 26), AbstractC0590b0.c(z, androidx.compose.material3.tokens.k.h), C0861v.b(AbstractC0590b0.c(z, androidx.compose.material3.tokens.k.c), 0.12f), C0861v.b(AbstractC0590b0.c(z, androidx.compose.material3.tokens.k.e), 0.38f));
        z.K = k2;
        return k2;
    }

    public static K c(Z z) {
        K k = z.M;
        if (k != null) {
            return k;
        }
        long j = C0861v.f;
        K k2 = new K(j, AbstractC0590b0.c(z, 26), j, C0861v.b(AbstractC0590b0.c(z, 18), 0.38f));
        z.M = k2;
        return k2;
    }
}
