package androidx.compose.ui.layout;

import androidx.compose.runtime.AbstractC0827t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class d0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d0(e0 e0Var, int i) {
        super(2);
        this.a = i;
        this.b = e0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                this.b.a().b = (AbstractC0827t) obj2;
                break;
            case 1:
                G gA = this.b.a();
                ((androidx.compose.ui.node.E) obj).Y(new D(gA, (Function2) obj2, gA.p));
                break;
            default:
                androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) obj;
                G g = e.y;
                e0 e0Var = this.b;
                if (g == null) {
                    g = new G(e, e0Var.a);
                    e.y = g;
                }
                e0Var.b = g;
                e0Var.a().e();
                G gA2 = e0Var.a();
                h0 h0Var = gA2.c;
                h0 h0Var2 = e0Var.a;
                if (h0Var != h0Var2) {
                    gA2.c = h0Var2;
                    gA2.f(false);
                    androidx.compose.ui.node.E.T(gA2.a, false, 7);
                }
                break;
        }
        return Unit.a;
    }
}
