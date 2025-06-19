package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Y2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function2 a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ float i;
    public final /* synthetic */ Function1 j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;
    public final /* synthetic */ androidx.compose.runtime.internal.d l;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y2(Function2 function2, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, androidx.compose.runtime.internal.d dVar6, boolean z, float f, Function1 function1, androidx.compose.runtime.internal.d dVar7, androidx.compose.runtime.internal.d dVar8, androidx.compose.foundation.layout.A0 a0, int i, int i2) {
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
        this.j = function1;
        this.k = dVar7;
        this.l = dVar8;
        this.m = a0;
        this.n = i;
        this.o = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.n | 1);
        int iH2 = C0776c.H(this.o);
        androidx.compose.runtime.internal.d dVar = this.k;
        AbstractC0587a3.c(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, dVar, this.l, this.m, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
