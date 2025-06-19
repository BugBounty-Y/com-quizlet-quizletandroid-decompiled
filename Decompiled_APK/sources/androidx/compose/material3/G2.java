package androidx.compose.material3;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class G2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.W0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ G2(androidx.compose.runtime.W0 w0, int i) {
        super(1);
        this.a = i;
        this.b = w0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((androidx.compose.ui.graphics.S) obj).b(((Number) this.b.getValue()).floatValue());
                return Unit.a;
            default:
                return new androidx.compose.ui.unit.h(P5.b(((androidx.compose.ui.unit.b) obj).m0(((androidx.compose.ui.unit.e) this.b.getValue()).a), 0));
        }
    }
}
