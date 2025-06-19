package androidx.compose.material3;

import androidx.compose.ui.graphics.AbstractC0857q;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ L0(Object obj, long j, int i) {
        super(0);
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((Function1) this.c).invoke(Long.valueOf(this.b));
                return Unit.a;
            case 1:
                androidx.compose.ui.node.P pU0 = ((androidx.compose.ui.node.L) this.c).a().U0();
                Intrinsics.d(pU0);
                pU0.B(this.b);
                return Unit.a;
            default:
                return ((androidx.compose.ui.graphics.T) ((AbstractC0857q) this.c)).b(this.b);
        }
    }
}
