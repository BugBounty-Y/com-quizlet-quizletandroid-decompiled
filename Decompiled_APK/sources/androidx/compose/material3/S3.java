package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.ui.graphics.V d;
    public final /* synthetic */ long e;
    public final /* synthetic */ long f;
    public final /* synthetic */ long g;
    public final /* synthetic */ long h;
    public final /* synthetic */ androidx.compose.runtime.internal.d i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S3(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.ui.graphics.V v, long j, long j2, long j3, long j4, androidx.compose.runtime.internal.d dVar3, int i, int i2) {
        super(2);
        this.a = qVar;
        this.b = dVar;
        this.c = dVar2;
        this.d = v;
        this.e = j;
        this.f = j2;
        this.g = j3;
        this.h = j4;
        this.i = dVar3;
        this.j = i;
        this.k = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        androidx.compose.runtime.internal.d dVar = this.i;
        long j = this.g;
        int i = this.k;
        T3.a(this.a, this.b, this.c, this.d, this.e, this.f, j, this.h, dVar, (InterfaceC0806l) obj, iH, i);
        return Unit.a;
    }
}
