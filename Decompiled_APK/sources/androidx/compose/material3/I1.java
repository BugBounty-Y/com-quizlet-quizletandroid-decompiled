package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class I1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ G1 d;
    public final /* synthetic */ float e;
    public final /* synthetic */ float f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I1(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, G1 g1, float f, float f2, int i) {
        super(2);
        this.a = dVar;
        this.b = qVar;
        this.c = dVar2;
        this.d = g1;
        this.e = f;
        this.f = f2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(7);
        androidx.compose.runtime.internal.d dVar = this.a;
        G1 g1 = this.d;
        L1.a(dVar, this.b, this.c, g1, this.e, this.f, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
