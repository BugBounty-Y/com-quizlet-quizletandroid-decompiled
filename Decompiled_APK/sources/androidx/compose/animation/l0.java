package androidx.compose.animation;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class l0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ m0 a;
    public final /* synthetic */ long b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;
    public final /* synthetic */ androidx.compose.ui.layout.M e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l0(m0 m0Var, long j, int i, int i2, androidx.compose.ui.layout.M m, androidx.compose.ui.layout.W w) {
        super(1);
        this.a = m0Var;
        this.b = j;
        this.c = i;
        this.d = i2;
        this.e = m;
        this.f = w;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        this.a.getClass();
        long jA = R5.a(this.c, this.d);
        androidx.compose.ui.unit.k layoutDirection = this.e.getLayoutDirection();
        long j = this.b;
        float f = (((int) (jA >> 32)) - ((int) (j >> 32))) / 2.0f;
        float f2 = (((int) (jA & 4294967295L)) - ((int) (j & 4294967295L))) / 2.0f;
        float f3 = layoutDirection == androidx.compose.ui.unit.k.a ? -1.0f : (-1) * (-1.0f);
        float f4 = 1;
        androidx.compose.ui.layout.V.e(v, this.f, P5.b(Math.round((f3 + f4) * f), Math.round((f4 - 1.0f) * f2)));
        return Unit.a;
    }
}
