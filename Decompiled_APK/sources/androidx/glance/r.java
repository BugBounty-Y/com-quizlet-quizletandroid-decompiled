package androidx.glance;

import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class r extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ a a;
    public final /* synthetic */ String b;
    public final /* synthetic */ p c;
    public final /* synthetic */ int d;
    public final /* synthetic */ f e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(a aVar, String str, p pVar, int i, f fVar, int i2, int i3) {
        super(2);
        this.a = aVar;
        this.b = str;
        this.c = pVar;
        this.d = i;
        this.e = fVar;
        this.f = i2;
        this.g = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int i = this.f | 1;
        a aVar = this.a;
        p pVar = this.c;
        AbstractC3189k7.c(aVar, this.b, pVar, this.d, this.e, (InterfaceC0806l) obj, i, this.g);
        return Unit.a;
    }
}
