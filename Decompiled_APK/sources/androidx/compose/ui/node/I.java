package androidx.compose.ui.node;

import androidx.compose.ui.platform.C0971v;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ L a;
    public final /* synthetic */ g0 b;
    public final /* synthetic */ long c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(L l, g0 g0Var, long j) {
        super(0);
        this.a = l;
        this.b = g0Var;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        P pU0;
        L l = this.a;
        androidx.compose.ui.layout.V placementScope = null;
        if (AbstractC0910f.r(l.a)) {
            a0 a0Var = l.a().n;
            if (a0Var != null) {
                placementScope = a0Var.i;
            }
        } else {
            a0 a0Var2 = l.a().n;
            if (a0Var2 != null && (pU0 = a0Var2.U0()) != null) {
                placementScope = pU0.i;
            }
        }
        if (placementScope == null) {
            placementScope = ((C0971v) this.b).getPlacementScope();
        }
        P pU02 = l.a().U0();
        Intrinsics.d(pU02);
        androidx.compose.ui.layout.V.e(placementScope, pU02, this.c);
        return Unit.a;
    }
}
