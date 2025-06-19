package androidx.compose.material3;

import androidx.compose.runtime.InterfaceC0773a0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class U1 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ androidx.compose.animation.core.T b;
    public final /* synthetic */ InterfaceC0773a0 c;
    public final /* synthetic */ androidx.compose.animation.core.z0 d;
    public final /* synthetic */ androidx.compose.animation.core.z0 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U1(boolean z, androidx.compose.animation.core.T t, InterfaceC0773a0 interfaceC0773a0, androidx.compose.animation.core.z0 z0Var, androidx.compose.animation.core.z0 z0Var2) {
        super(1);
        this.a = z;
        this.b = t;
        this.c = interfaceC0773a0;
        this.d = z0Var;
        this.e = z0Var2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.graphics.S s = (androidx.compose.ui.graphics.S) obj;
        androidx.compose.animation.core.T t = this.b;
        float fFloatValue = 0.8f;
        androidx.compose.animation.core.z0 z0Var = this.d;
        float fFloatValue2 = 1.0f;
        InterfaceC0773a0 interfaceC0773a0 = t.d;
        boolean z = this.a;
        s.m(!z ? ((Number) z0Var.getValue()).floatValue() : ((Boolean) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).booleanValue() ? 1.0f : 0.8f);
        if (!z) {
            fFloatValue = ((Number) z0Var.getValue()).floatValue();
        } else if (((Boolean) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).booleanValue()) {
            fFloatValue = 1.0f;
        }
        s.o(fFloatValue);
        if (!z) {
            fFloatValue2 = ((Number) this.e.getValue()).floatValue();
        } else if (!((Boolean) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).booleanValue()) {
            fFloatValue2 = DefinitionKt.NO_Float_VALUE;
        }
        s.b(fFloatValue2);
        s.x(((androidx.compose.ui.graphics.Z) this.c.getValue()).a);
        return Unit.a;
    }
}
