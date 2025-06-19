package androidx.compose.foundation;

import androidx.compose.foundation.gestures.C0326g0;
import androidx.compose.foundation.gestures.U0;
import androidx.compose.foundation.gestures.k1;
import kotlin.Unit;

/* loaded from: classes.dex */
public class E extends AbstractC0368j {
    @Override // androidx.compose.foundation.AbstractC0368j
    public final Object Q0(androidx.compose.ui.input.pointer.B b, C0366i c0366i) {
        D d = new D(this, null, 0);
        androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(this, 8);
        androidx.compose.foundation.gestures.S s = k1.a;
        Object objM = kotlinx.coroutines.E.m(new U0(b, d, fVar, new C0326g0(b), null), c0366i);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objM != aVar) {
            objM = Unit.a;
        }
        return objM == aVar ? objM : Unit.a;
    }
}
