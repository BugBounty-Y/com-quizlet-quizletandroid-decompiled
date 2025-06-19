package androidx.compose.material;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3244r0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class i0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.ui.graphics.V b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ float e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i0(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, long j2, float f, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = qVar;
        this.b = v;
        this.c = j;
        this.d = j2;
        this.e = f;
        this.f = dVar;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.g | 1);
        androidx.compose.runtime.internal.d dVar = this.f;
        long j = this.c;
        long j2 = this.d;
        AbstractC3244r0.c(this.a, this.b, j, j2, this.e, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
