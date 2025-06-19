package androidx.glance.layout;

import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class q extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.glance.p a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(androidx.glance.p pVar, int i, int i2, androidx.compose.runtime.internal.d dVar, int i3, int i4) {
        super(2);
        this.a = pVar;
        this.b = i;
        this.c = i2;
        this.d = dVar;
        this.e = i4;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        androidx.compose.runtime.internal.d dVar = this.d;
        int i = this.b;
        int i2 = this.e;
        AbstractC3328d.c(this.a, i, this.c, dVar, (InterfaceC0806l) obj, 3073, i2);
        return Unit.a;
    }
}
