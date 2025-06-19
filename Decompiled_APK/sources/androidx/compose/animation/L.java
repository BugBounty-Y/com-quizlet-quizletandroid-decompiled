package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.H0;
import androidx.compose.runtime.L0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ E0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ L(E0 e0, int i) {
        super(1);
        this.a = i;
        this.b = e0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(!Intrinsics.b(obj, ((L0) this.b.d).getValue()));
            case 1:
                return new H0(this.b, 0);
            default:
                return new H0(this.b, 1);
        }
    }
}
