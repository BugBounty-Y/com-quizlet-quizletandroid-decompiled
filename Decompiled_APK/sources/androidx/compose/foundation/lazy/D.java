package androidx.compose.foundation.lazy;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public abstract class D {
    public static final float a = 1;
    public static final q b = new q(null, 0, false, DefinitionKt.NO_Float_VALUE, new B(0), DefinitionKt.NO_Float_VALUE, false, kotlinx.coroutines.E.c(kotlin.coroutines.n.a), M5.b(), L5.b(0, 0, 15), K.a, 0, 0, 0, EnumC0320d0.a, 0, 0);

    public static final A a(int i, InterfaceC0806l interfaceC0806l, int i2) {
        if ((i2 & 1) != 0) {
            i = 0;
        }
        Object[] objArr = new Object[0];
        com.quizlet.data.repository.explanations.myexplanations.a aVar = A.x;
        boolean zD = ((C0814p) interfaceC0806l).d(i) | ((C0814p) interfaceC0806l).d(0);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (zD || objI == C0804k.a) {
            objI = new C(i, 0);
            c0814p.i0(objI);
        }
        return (A) L4.d(objArr, aVar, (Function0) objI, c0814p, 0, 4);
    }
}
