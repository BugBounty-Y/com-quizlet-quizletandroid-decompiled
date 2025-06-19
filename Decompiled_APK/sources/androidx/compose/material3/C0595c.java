package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0595c extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ androidx.compose.ui.n b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.ui.graphics.V e;
    public final /* synthetic */ long f;
    public final /* synthetic */ float g;
    public final /* synthetic */ long h;
    public final /* synthetic */ long i;
    public final /* synthetic */ long j;
    public final /* synthetic */ long k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0595c(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.ui.graphics.V v, long j, float f, long j2, long j3, long j4, long j5, int i) {
        super(2);
        this.a = dVar;
        this.b = nVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = v;
        this.f = j;
        this.g = f;
        this.h = j2;
        this.i = j3;
        this.j = j4;
        this.k = j5;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(7);
        androidx.compose.runtime.internal.d dVar = this.a;
        long j = this.h;
        long j2 = this.i;
        AbstractC0625h.a(dVar, this.b, this.c, this.d, this.e, this.f, this.g, j, j2, this.j, this.k, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
