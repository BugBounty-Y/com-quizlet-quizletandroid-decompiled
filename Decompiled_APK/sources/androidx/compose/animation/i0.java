package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.InterfaceC0256n;
import androidx.compose.animation.core.L0;
import androidx.compose.animation.core.M0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class i0 {
    public static final W0 a(long j, InterfaceC0256n interfaceC0256n, String str, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3 = 3;
        if ((i2 & 4) != 0) {
            str = "ColorAnimation";
        }
        String str2 = str;
        if ((i2 & 8) != 0) {
            function1 = null;
        }
        Function1 function12 = function1;
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zF = c0814p.f(C0861v.f(j));
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            androidx.compose.ui.graphics.colorspace.c cVarF = C0861v.f(j);
            C0229c c0229c = C0229c.g;
            androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(cVarF, i3);
            L0 l0 = M0.a;
            L0 l02 = new L0(c0229c, fVar);
            c0814p.i0(l02);
            objI = l02;
        }
        int i4 = i << 6;
        return AbstractC0248j.c(new C0861v(j), (L0) objI, interfaceC0256n, null, str2, function12, c0814p, (i & 14) | ((i << 3) & 896) | (57344 & i4) | (i4 & 458752), 8);
    }
}
