package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.H0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F2(androidx.compose.runtime.H0 h0, int i) {
        super(1);
        this.a = i;
        this.b = h0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.j((int) (((androidx.compose.ui.unit.j) obj).a >> 32));
                break;
            default:
                this.b.j(((Number) obj).intValue());
                break;
        }
        return Unit.a;
    }
}
