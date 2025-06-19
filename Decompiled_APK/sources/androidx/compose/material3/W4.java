package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0276z;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public abstract class W4 {
    public static final float a;
    public static final float b;
    public static final float c;
    public static final float d;
    public static final float e;

    static {
        float f = androidx.compose.material3.tokens.D.a;
        a = f;
        b = f;
        c = androidx.compose.material3.tokens.C.a;
        d = f;
        e = androidx.compose.material3.tokens.B.a;
    }

    public static com.quizlet.data.repository.achievements.h a(X4 x4, InterfaceC0806l interfaceC0806l, int i) {
        C0253l0 c0253l0Q = (i & 4) != 0 ? AbstractC0240f.q(5, null) : null;
        C0276z c0276zA = (i & 8) != 0 ? androidx.compose.animation.p0.a(interfaceC0806l) : null;
        com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h();
        hVar.a = x4;
        hVar.b = c0253l0Q;
        hVar.c = c0276zA;
        hVar.d = new C0670k1(hVar);
        return hVar;
    }

    public static C0416v0 b(InterfaceC0806l interfaceC0806l) {
        WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
        androidx.compose.foundation.layout.S0 s0E = C0380d.e(interfaceC0806l);
        return new C0416v0(s0E.g, AbstractC0382e.g | 16);
    }

    public static V4 c(long j, long j2, long j3, long j4, InterfaceC0806l interfaceC0806l, int i) {
        V4 v4;
        long j5 = (i & 2) != 0 ? C0861v.g : j2;
        long j6 = (i & 4) != 0 ? C0861v.g : j3;
        long j7 = (i & 8) != 0 ? C0861v.g : j4;
        long j8 = C0861v.g;
        Z z = (Z) ((C0814p) interfaceC0806l).j(AbstractC0590b0.a);
        V4 v42 = z.O;
        if (v42 == null) {
            float f = androidx.compose.material3.tokens.D.a;
            V4 v43 = new V4(AbstractC0590b0.c(z, 35), AbstractC0590b0.c(z, androidx.compose.material3.tokens.D.e), AbstractC0590b0.c(z, androidx.compose.material3.tokens.D.d), AbstractC0590b0.c(z, androidx.compose.material3.tokens.D.b), AbstractC0590b0.c(z, androidx.compose.material3.tokens.D.f));
            z.O = v43;
            v4 = v43;
        } else {
            v4 = v42;
        }
        return v4.a(j, j5, j6, j7, j8);
    }
}
