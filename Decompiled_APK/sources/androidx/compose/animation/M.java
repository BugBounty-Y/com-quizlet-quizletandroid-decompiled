package androidx.compose.animation;

import androidx.compose.animation.core.z0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class M extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ z0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ M(z0 z0Var, int i) {
        super(1);
        this.a = i;
        this.b = z0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((androidx.compose.ui.graphics.S) obj).b(((Number) this.b.getValue()).floatValue());
                break;
            default:
                ((androidx.compose.ui.graphics.S) obj).b(((Number) this.b.getValue()).floatValue());
                break;
        }
        return Unit.a;
    }
}
