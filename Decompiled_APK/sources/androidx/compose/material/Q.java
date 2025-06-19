package androidx.compose.material;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Q extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ e0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.foundation.shape.d e;
    public final /* synthetic */ float f;
    public final /* synthetic */ long g;
    public final /* synthetic */ long h;
    public final /* synthetic */ long i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, e0 e0Var, boolean z, androidx.compose.foundation.shape.d dVar2, float f, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar3, int i) {
        super(2);
        this.a = dVar;
        this.b = qVar;
        this.c = e0Var;
        this.d = z;
        this.e = dVar2;
        this.f = f;
        this.g = j;
        this.h = j2;
        this.i = j3;
        this.j = dVar3;
        this.k = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.k | 1);
        androidx.compose.runtime.internal.d dVar = this.j;
        long j = this.g;
        long j2 = this.h;
        Z.a(this.a, this.b, this.c, this.d, this.e, this.f, j, j2, this.i, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
