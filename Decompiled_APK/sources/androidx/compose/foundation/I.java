package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class I extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ J b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ I(J j, int i) {
        super(1);
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                long j = ((androidx.compose.ui.geometry.b) obj).a;
                Function0 function0 = this.b.H;
                if (function0 != null) {
                    function0.invoke();
                }
                break;
            default:
                long j2 = ((androidx.compose.ui.geometry.b) obj).a;
                J j3 = this.b;
                if (j3.t) {
                    j3.u.invoke();
                }
                break;
        }
        return Unit.a;
    }
}
