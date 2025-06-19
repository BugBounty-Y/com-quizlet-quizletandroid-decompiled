package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function2 a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ float i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J4(Function2 function2, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, androidx.compose.runtime.internal.d dVar6, boolean z, float f, androidx.compose.runtime.internal.d dVar7, androidx.compose.runtime.internal.d dVar8, androidx.compose.foundation.layout.A0 a0, int i, int i2) {
        super(2);
        this.a = function2;
        this.b = dVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = dVar4;
        this.f = dVar5;
        this.g = dVar6;
        this.h = z;
        this.i = f;
        this.j = dVar7;
        this.k = dVar8;
        this.l = a0;
        this.m = i;
        this.n = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.m | 1);
        int iH2 = C0776c.H(this.n);
        androidx.compose.runtime.internal.d dVar = this.j;
        K4.c(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, dVar, this.k, this.l, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
