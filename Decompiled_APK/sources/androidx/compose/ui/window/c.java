package androidx.compose.ui.window;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class c extends kotlin.jvm.internal.r implements Function1 {
    public static final c b = new c(1, 0);
    public static final c c = new c(1, 1);
    public static final c d = new c(1, 2);
    public static final c e = new c(1, 3);
    public static final c f = new c(1, 4);
    public static final c g = new c(1, 5);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.r;
                Unit unit = Unit.a;
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(uVar, unit);
                break;
            case 1:
                ((Number) obj).longValue();
                break;
            case 2:
                break;
            case 3:
                kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.q;
                Unit unit2 = Unit.a;
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(uVar2, unit2);
                break;
            case 4:
                break;
            default:
                u uVar3 = (u) obj;
                if (uVar3.isAttachedToWindow()) {
                    uVar3.i();
                }
                break;
        }
        return Unit.a;
    }
}
