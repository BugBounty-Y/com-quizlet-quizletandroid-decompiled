package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class D0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ float d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D0(androidx.compose.runtime.internal.d dVar, long j, long j2, float f, androidx.compose.runtime.internal.d dVar2, int i) {
        super(2);
        this.a = dVar;
        this.b = j;
        this.c = j2;
        this.d = f;
        this.e = dVar2;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        androidx.compose.runtime.internal.d dVar = this.e;
        long j = this.b;
        long j2 = this.c;
        Z0.c(this.a, j, j2, this.d, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
