package androidx.compose.foundation.lazy;

import androidx.compose.foundation.lazy.layout.U;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.collections.L;
import kotlin.collections.V;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class l extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ U b;
    public final /* synthetic */ long c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(U u, long j, int i, int i2, int i3) {
        super(3);
        this.a = i3;
        this.b = u;
        this.c = j;
        this.d = i;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                int iIntValue = ((Number) obj).intValue();
                int iIntValue2 = ((Number) obj2).intValue();
                int i = iIntValue + this.d;
                long j = this.c;
                int iL = L5.l(i, j);
                int iK = L5.k(iIntValue2 + this.e, j);
                L lC = V.c();
                return this.b.b.n0(iL, iK, lC, (Function1) obj3);
            case 1:
                int iIntValue3 = ((Number) obj).intValue();
                int iIntValue4 = ((Number) obj2).intValue();
                int i2 = iIntValue3 + this.d;
                long j2 = this.c;
                int iL2 = L5.l(i2, j2);
                int iK2 = L5.k(iIntValue4 + this.e, j2);
                L lC2 = V.c();
                return this.b.b.n0(iL2, iK2, lC2, (Function1) obj3);
            default:
                int iIntValue5 = ((Number) obj).intValue();
                int iIntValue6 = ((Number) obj2).intValue();
                int i3 = iIntValue5 + this.d;
                long j3 = this.c;
                int iL3 = L5.l(i3, j3);
                int iK3 = L5.k(iIntValue6 + this.e, j3);
                L lC3 = V.c();
                return this.b.b.n0(iL3, iK3, lC3, (Function1) obj3);
        }
    }
}
