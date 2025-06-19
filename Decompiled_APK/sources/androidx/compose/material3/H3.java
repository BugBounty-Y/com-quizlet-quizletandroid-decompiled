package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ L3 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ H3(L3 l3, int i) {
        super(1);
        this.a = i;
        this.b = l3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.f(vVar);
                androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
                kVar.b(androidx.compose.ui.semantics.j.t, new androidx.compose.ui.semantics.a(null, new androidx.compose.animation.core.K(this.b, 21)));
                return Unit.a;
            default:
                return Boolean.valueOf(Intrinsics.b(((C0682m1) obj).a, this.b));
        }
    }
}
