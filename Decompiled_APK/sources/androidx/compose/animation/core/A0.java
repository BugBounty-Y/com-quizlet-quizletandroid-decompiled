package androidx.compose.animation.core;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class A0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ float b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A0(float f, InterfaceC0773a0 interfaceC0773a0) {
        super(1);
        this.b = f;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                long jLongValue = ((Number) obj).longValue();
                E0 e0 = (E0) this.c;
                if (!e0.h()) {
                    androidx.compose.runtime.J0 j0 = e0.g;
                    if (j0.i() == Long.MIN_VALUE) {
                        j0.j(jLongValue);
                        ((androidx.compose.runtime.L0) ((InterfaceC0773a0) e0.a.b)).setValue(Boolean.TRUE);
                    }
                    long jI = jLongValue - j0.i();
                    float f = this.b;
                    if (f != DefinitionKt.NO_Float_VALUE) {
                        jI = kotlin.math.c.c(jI / f);
                    }
                    e0.p(jI);
                    e0.i(jI, f == DefinitionKt.NO_Float_VALUE);
                }
                break;
            default:
                long j = ((androidx.compose.ui.geometry.e) obj).a;
                float fD = androidx.compose.ui.geometry.e.d(j);
                float f2 = this.b;
                float f3 = fD * f2;
                float fB = androidx.compose.ui.geometry.e.b(j) * f2;
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.c;
                if (androidx.compose.ui.geometry.e.d(((androidx.compose.ui.geometry.e) interfaceC0773a0.getValue()).a) != f3 || androidx.compose.ui.geometry.e.b(((androidx.compose.ui.geometry.e) interfaceC0773a0.getValue()).a) != fB) {
                    interfaceC0773a0.setValue(new androidx.compose.ui.geometry.e(T4.a(f3, fB)));
                }
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A0(E0 e0, float f) {
        super(1);
        this.c = e0;
        this.b = f;
    }
}
