package androidx.compose.material;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class M extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e0 b;
    public final /* synthetic */ kotlinx.coroutines.C c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ M(e0 e0Var, kotlinx.coroutines.C c, int i) {
        super(0);
        this.a = i;
        this.b = e0Var;
        this.c = c;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        kotlinx.coroutines.C c = this.c;
        e0 e0Var = this.b;
        switch (this.a) {
            case 0:
                e0Var.a.getClass();
                f0 f0Var = f0.a;
                if (Boolean.TRUE.booleanValue()) {
                    kotlinx.coroutines.E.A(c, null, null, new L(e0Var, null), 3);
                }
                return Unit.a;
            case 1:
                e0Var.a.getClass();
                f0 f0Var2 = f0.a;
                Boolean bool = Boolean.TRUE;
                if (bool.booleanValue()) {
                    kotlinx.coroutines.E.A(c, null, null, new N(e0Var, null), 3);
                }
                return bool;
            case 2:
                e0Var.a.getClass();
                f0 f0Var3 = f0.a;
                Boolean bool2 = Boolean.TRUE;
                if (bool2.booleanValue()) {
                    kotlinx.coroutines.E.A(c, null, null, new O(e0Var, null), 3);
                }
                return bool2;
            default:
                e0Var.a.getClass();
                f0 f0Var4 = f0.a;
                Boolean bool3 = Boolean.TRUE;
                if (bool3.booleanValue()) {
                    kotlinx.coroutines.E.A(c, null, null, new P(e0Var, null), 3);
                }
                return bool3;
        }
    }
}
