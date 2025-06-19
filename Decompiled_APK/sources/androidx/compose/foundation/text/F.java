package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ C0492h0 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.text.input.B d;
    public final /* synthetic */ androidx.compose.ui.text.input.A e;
    public final /* synthetic */ androidx.compose.ui.text.input.m f;
    public final /* synthetic */ androidx.compose.ui.text.input.s g;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 h;
    public final /* synthetic */ kotlinx.coroutines.C i;
    public final /* synthetic */ androidx.compose.foundation.relocation.c j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(C0492h0 c0492h0, boolean z, boolean z2, androidx.compose.ui.text.input.B b, androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.m mVar, androidx.compose.ui.text.input.s sVar, androidx.compose.foundation.text.selection.i0 i0Var, kotlinx.coroutines.C c, androidx.compose.foundation.relocation.c cVar) {
        super(1);
        this.a = c0492h0;
        this.b = z;
        this.c = z2;
        this.d = b;
        this.e = a;
        this.f = mVar;
        this.g = sVar;
        this.h = i0Var;
        this.i = c;
        this.j = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        K0 k0D;
        androidx.compose.ui.focus.s sVar = (androidx.compose.ui.focus.s) obj;
        C0492h0 c0492h0 = this.a;
        if (c0492h0.b() != sVar.a()) {
            ((androidx.compose.runtime.L0) c0492h0.f).setValue(Boolean.valueOf(sVar.a()));
            if (c0492h0.b() && this.b && !this.c) {
                AbstractC0484d0.o(this.d, c0492h0, this.e, this.f, this.g);
            } else {
                AbstractC0484d0.k(c0492h0);
            }
            if (sVar.a() && (k0D = c0492h0.d()) != null) {
                kotlinx.coroutines.E.A(this.i, null, null, new E(this.j, this.e, c0492h0, k0D, this.g, null), 3);
            }
            if (!sVar.a()) {
                this.h.g(null);
            }
        }
        return Unit.a;
    }
}
