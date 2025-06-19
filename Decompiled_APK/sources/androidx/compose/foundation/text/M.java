package androidx.compose.foundation.text;

import androidx.compose.animation.core.C0242g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class M extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.text.input.I a;
    public final /* synthetic */ androidx.compose.ui.text.input.A b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ androidx.compose.ui.text.input.m f;
    public final /* synthetic */ C0492h0 g;
    public final /* synthetic */ androidx.compose.ui.text.input.s h;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 i;
    public final /* synthetic */ androidx.compose.ui.focus.p j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(androidx.compose.ui.text.input.I i, androidx.compose.ui.text.input.A a, boolean z, boolean z2, boolean z3, androidx.compose.ui.text.input.m mVar, C0492h0 c0492h0, androidx.compose.ui.text.input.s sVar, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.focus.p pVar) {
        super(1);
        this.a = i;
        this.b = a;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = mVar;
        this.g = c0492h0;
        this.h = sVar;
        this.i = i0Var;
        this.j = pVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0492h0 c0492h0;
        androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
        androidx.compose.ui.text.input.I i = this.a;
        kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.x;
        kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
        kotlin.reflect.n nVar = nVarArr2[16];
        uVar.a(vVar, i.a);
        androidx.compose.ui.text.input.A a = this.b;
        long j = a.b;
        androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.y;
        kotlin.reflect.n nVar2 = nVarArr2[17];
        uVar2.a(vVar, new androidx.compose.ui.text.K(j));
        boolean z = this.c;
        if (!z) {
            ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.r.i, Unit.a);
        }
        boolean z2 = this.d;
        if (z2) {
            ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.r.C, Unit.a);
        }
        boolean z3 = this.e;
        boolean z4 = z && !z3;
        androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.F;
        kotlin.reflect.n nVar3 = nVarArr2[23];
        uVar3.a(vVar, Boolean.valueOf(z4));
        C0492h0 c0492h02 = this.g;
        androidx.compose.ui.semantics.t.c(vVar, new D(c0492h02, 2));
        if (z4) {
            androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
            kVar.b(androidx.compose.ui.semantics.j.i, new androidx.compose.ui.semantics.a(null, new D(c0492h02, vVar)));
            c0492h0 = c0492h02;
            kVar.b(androidx.compose.ui.semantics.j.m, new androidx.compose.ui.semantics.a(null, new J(this.e, this.c, c0492h02, vVar, this.b)));
        } else {
            c0492h0 = c0492h02;
        }
        androidx.compose.foundation.text.selection.i0 i0Var = this.i;
        C0492h0 c0492h03 = c0492h0;
        androidx.compose.ui.semantics.k kVar2 = (androidx.compose.ui.semantics.k) vVar;
        kVar2.b(androidx.compose.ui.semantics.j.h, new androidx.compose.ui.semantics.a(null, new K(this.h, this.c, this.b, i0Var, c0492h0)));
        androidx.compose.ui.text.input.m mVar = this.f;
        int i2 = mVar.e;
        C0242g c0242g = new C0242g(7, c0492h03, mVar);
        kVar2.b(androidx.compose.ui.semantics.r.z, new androidx.compose.ui.text.input.l(i2));
        kVar2.b(androidx.compose.ui.semantics.j.n, new androidx.compose.ui.semantics.a(null, c0242g));
        kVar2.b(androidx.compose.ui.semantics.j.b, new androidx.compose.ui.semantics.a(null, new L(c0492h03, this.j, z3)));
        kVar2.b(androidx.compose.ui.semantics.j.c, new androidx.compose.ui.semantics.a(null, new I(i0Var, 1)));
        if (!androidx.compose.ui.text.K.b(a.b) && !z2) {
            kVar2.b(androidx.compose.ui.semantics.j.o, new androidx.compose.ui.semantics.a(null, new I(i0Var, 2)));
            if (z && !z3) {
                kVar2.b(androidx.compose.ui.semantics.j.p, new androidx.compose.ui.semantics.a(null, new I(i0Var, 3)));
            }
        }
        if (z && !z3) {
            kVar2.b(androidx.compose.ui.semantics.j.q, new androidx.compose.ui.semantics.a(null, new I(i0Var, 0)));
        }
        return Unit.a;
    }
}
