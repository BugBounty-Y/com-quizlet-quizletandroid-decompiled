package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public abstract class B {
    public static final q a;

    static {
        androidx.compose.foundation.lazy.B b = new androidx.compose.foundation.lazy.B(1);
        K k = K.a;
        EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
        E.c(kotlin.coroutines.n.a);
        a = new q(null, 0, false, DefinitionKt.NO_Float_VALUE, b, false, 0, o.e, k, 0, 0, 0, enumC0320d0, 0, 0);
    }

    public static final A a(int i, InterfaceC0806l interfaceC0806l, int i2) {
        if ((i2 & 1) != 0) {
            i = 0;
        }
        Object[] objArr = new Object[0];
        com.quizlet.data.repository.explanations.myexplanations.a aVar = A.t;
        boolean zD = ((C0814p) interfaceC0806l).d(i) | ((C0814p) interfaceC0806l).d(0);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (zD || objI == C0804k.a) {
            objI = new androidx.compose.foundation.lazy.C(i, 1);
            c0814p.i0(objI);
        }
        return (A) L4.d(objArr, aVar, (Function0) objI, c0814p, 0, 4);
    }
}
