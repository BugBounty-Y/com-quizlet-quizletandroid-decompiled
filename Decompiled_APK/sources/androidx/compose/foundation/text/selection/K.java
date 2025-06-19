package androidx.compose.foundation.text.selection;

import androidx.compose.animation.core.C0262q;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class K extends kotlin.jvm.internal.r implements Function1 {
    public static final K b = new K(1, 0);
    public static final K c = new K(1, 1);
    public static final K d = new K(1, 2);
    public static final K e = new K(1, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ K(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                long j = ((androidx.compose.ui.geometry.b) obj).a;
                return Q4.h(j) ? new C0262q(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j)) : O.a;
            case 1:
                C0262q c0262q = (C0262q) obj;
                return new androidx.compose.ui.geometry.b(Q4.c(c0262q.a, c0262q.b));
            case 2:
                return new b0(((Number) obj).longValue());
            default:
                return Unit.a;
        }
    }
}
