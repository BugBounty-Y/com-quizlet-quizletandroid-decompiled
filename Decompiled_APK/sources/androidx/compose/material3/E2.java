package androidx.compose.material3;

import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ float d;
    public final /* synthetic */ C0416v0 e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E2(androidx.compose.ui.q qVar, long j, long j2, float f, C0416v0 c0416v0, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = qVar;
        this.b = j;
        this.c = j2;
        this.d = f;
        this.e = c0416v0;
        this.f = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(196609);
        androidx.compose.runtime.internal.d dVar = this.f;
        long j = this.c;
        float f = this.d;
        M2.a(this.a, this.b, j, f, this.e, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
