package androidx.compose.foundation.pager;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.lazy.layout.U;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3200m0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class v extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ U b;
    public final /* synthetic */ long c;
    public final /* synthetic */ u d;
    public final /* synthetic */ long e;
    public final /* synthetic */ androidx.compose.ui.h f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ v(U u, long j, u uVar, long j2, androidx.compose.ui.h hVar, int i, int i2) {
        super(1);
        this.a = i2;
        this.b = u;
        this.c = j;
        this.d = uVar;
        this.e = j2;
        this.f = hVar;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                int iIntValue = ((Number) obj).intValue();
                U u = this.b;
                androidx.compose.ui.unit.k layoutDirection = u.b.getLayoutDirection();
                return AbstractC3200m0.b(u, iIntValue, this.c, this.d, this.e, EnumC0320d0.b, androidx.compose.ui.b.n, this.f, layoutDirection, false, this.g);
            default:
                int iIntValue2 = ((Number) obj).intValue();
                U u2 = this.b;
                androidx.compose.ui.unit.k layoutDirection2 = u2.b.getLayoutDirection();
                return AbstractC3200m0.b(u2, iIntValue2, this.c, this.d, this.e, EnumC0320d0.b, androidx.compose.ui.b.n, this.f, layoutDirection2, false, this.g);
        }
    }
}
