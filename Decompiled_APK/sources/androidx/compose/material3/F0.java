package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F0(int i, Function1 function1) {
        super(0);
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(new C0615f1(1));
                break;
            case 1:
                this.b.invoke(new C0615f1(0));
                break;
            default:
                androidx.compose.ui.graphics.S s = androidx.compose.ui.node.a0.F;
                this.b.invoke(s);
                s.v = s.o.e(s.r, s.t, s.s);
                break;
        }
        return Unit.a;
    }
}
