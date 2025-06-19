package androidx.compose.foundation.text;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.platform.e1;
import androidx.compose.ui.platform.f1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ C0492h0 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ e1 c;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 d;
    public final /* synthetic */ androidx.compose.ui.text.input.A e;
    public final /* synthetic */ androidx.compose.ui.text.input.s f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(C0492h0 c0492h0, boolean z, e1 e1Var, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.s sVar) {
        super(1);
        this.a = c0492h0;
        this.b = z;
        this.c = e1Var;
        this.d = i0Var;
        this.e = a;
        this.f = sVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.text.input.H h;
        androidx.compose.ui.layout.r rVar;
        androidx.compose.ui.layout.r rVar2;
        androidx.compose.ui.layout.r rVar3 = (androidx.compose.ui.layout.r) obj;
        C0492h0 c0492h0 = this.a;
        c0492h0.h = rVar3;
        K0 k0D = c0492h0.d();
        if (k0D != null) {
            k0D.b = rVar3;
        }
        if (this.b) {
            V vA = c0492h0.a();
            V v = V.b;
            androidx.compose.foundation.text.selection.i0 i0Var = this.d;
            InterfaceC0773a0 interfaceC0773a0 = c0492h0.o;
            androidx.compose.ui.text.input.A a = this.e;
            if (vA == v) {
                if (((Boolean) ((androidx.compose.runtime.L0) c0492h0.l).getValue()).booleanValue() && ((f1) this.c).a()) {
                    i0Var.q();
                } else {
                    i0Var.m();
                }
                ((androidx.compose.runtime.L0) c0492h0.m).setValue(Boolean.valueOf(androidx.compose.foundation.text.selection.W.w(i0Var, true)));
                ((androidx.compose.runtime.L0) c0492h0.n).setValue(Boolean.valueOf(androidx.compose.foundation.text.selection.W.w(i0Var, false)));
                ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(Boolean.valueOf(androidx.compose.ui.text.K.b(a.b)));
            } else if (c0492h0.a() == V.c) {
                ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(Boolean.valueOf(androidx.compose.foundation.text.selection.W.w(i0Var, true)));
            }
            AbstractC0484d0.w(c0492h0, a, this.f);
            K0 k0D2 = c0492h0.d();
            if (k0D2 != null && (h = c0492h0.e) != null && c0492h0.b() && (rVar = k0D2.b) != null && rVar.k() && (rVar2 = k0D2.c) != null) {
                androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(rVar, 21);
                androidx.compose.ui.geometry.c cVarY = androidx.compose.foundation.text.selection.W.y(rVar);
                androidx.compose.ui.geometry.c cVarO = rVar.o(rVar2, false);
                if (Intrinsics.b((androidx.compose.ui.text.input.H) h.a.b.get(), h)) {
                    h.b.c(this.e, this.f, k0D2.a, fVar, cVarY, cVarO);
                }
            }
        }
        return Unit.a;
    }
}
