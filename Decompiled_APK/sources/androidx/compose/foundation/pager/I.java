package androidx.compose.foundation.pager;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public abstract class I {
    public static final float a = 56;
    public static final x b;
    public static final F c;

    static {
        kotlin.collections.K k = kotlin.collections.K.a;
        androidx.compose.foundation.gestures.snapping.n nVar = androidx.compose.foundation.gestures.snapping.n.c;
        androidx.compose.foundation.lazy.B b2 = new androidx.compose.foundation.lazy.B(2);
        kotlinx.coroutines.E.c(kotlin.coroutines.n.a);
        b = new x(k, 0, 0, 0, 0, 0, 0, nVar, b2);
        c = new F();
    }

    public static final long a(x xVar, int i) {
        long j = (i * (xVar.c + xVar.b)) + (-xVar.f) + xVar.d;
        EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
        EnumC0320d0 enumC0320d02 = xVar.e;
        long jA = xVar.a();
        int i2 = (int) (enumC0320d02 == enumC0320d0 ? jA >> 32 : jA & 4294967295L);
        xVar.n.getClass();
        long jC = j - (i2 - kotlin.ranges.l.c(0, 0, i2));
        if (jC < 0) {
            return 0L;
        }
        return jC;
    }

    public static final C0466e b(int i, Function0 function0, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        boolean z = true;
        if ((i3 & 1) != 0) {
            i = 0;
        }
        Object[] objArr = new Object[0];
        com.quizlet.data.repository.explanations.myexplanations.a aVar = C0466e.I;
        boolean zD = ((C0814p) interfaceC0806l).d(i) | ((C0814p) interfaceC0806l).c(DefinitionKt.NO_Float_VALUE);
        if ((((i2 & 896) ^ 384) <= 256 || !((C0814p) interfaceC0806l).f(function0)) && (i2 & 384) != 256) {
            z = false;
        }
        boolean z2 = zD | z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (z2 || objI == C0804k.a) {
            objI = new H(i, function0);
            c0814p.i0(objI);
        }
        C0466e c0466e = (C0466e) L4.d(objArr, aVar, (Function0) objI, c0814p, 0, 4);
        ((L0) c0466e.H).setValue(function0);
        return c0466e;
    }
}
