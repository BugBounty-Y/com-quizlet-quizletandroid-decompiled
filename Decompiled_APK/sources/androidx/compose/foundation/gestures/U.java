package androidx.compose.foundation.gestures;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class U {
    public static final S a = new S(3, 0, null);
    public static final S b = new S(3, 1, null);

    public static androidx.compose.ui.q a(androidx.compose.ui.q qVar, Z z, EnumC0320d0 enumC0320d0, boolean z2, boolean z3, kotlin.jvm.functions.c cVar, int i) {
        if ((i & 4) != 0) {
            z2 = true;
        }
        boolean z4 = z2;
        if ((i & 16) != 0) {
            z3 = false;
        }
        return qVar.g(new DraggableElement(z, enumC0320d0, z4, null, z3, a, cVar, false));
    }

    public static final Z b(Function1 function1, InterfaceC0806l interfaceC0806l) {
        InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function1, interfaceC0806l);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            C0339n c0339n = new C0339n(new T(interfaceC0773a0D, 0));
            c0814p.i0(c0339n);
            objI = c0339n;
        }
        return (Z) objI;
    }
}
