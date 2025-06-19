package coil3.compose;

import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class n implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ W b;

    public /* synthetic */ n(W w, int i) {
        this.a = i;
        this.b = w;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        V layout = (V) obj;
        switch (this.a) {
            case 0:
                V.d(layout, this.b, 0, 0);
                break;
            case 1:
                V.f(layout, this.b, 0, 0);
                break;
            default:
                Intrinsics.checkNotNullParameter(layout, "$this$layout");
                W w = this.b;
                if (w != null) {
                    V.d(layout, w, 0, 0);
                }
                break;
        }
        return Unit.a;
    }
}
