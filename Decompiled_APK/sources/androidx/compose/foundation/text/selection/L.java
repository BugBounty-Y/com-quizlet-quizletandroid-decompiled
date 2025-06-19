package androidx.compose.foundation.text.selection;

import androidx.compose.animation.core.C0262q;
import androidx.compose.runtime.W0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class L extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ W0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ L(W0 w0, int i) {
        super(0);
        this.a = i;
        this.b = w0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        W0 w0 = this.b;
        switch (this.a) {
            case 0:
                C0262q c0262q = O.a;
                return new androidx.compose.ui.geometry.b(((androidx.compose.ui.geometry.b) w0.getValue()).a);
            default:
                return (Float) w0.getValue();
        }
    }
}
