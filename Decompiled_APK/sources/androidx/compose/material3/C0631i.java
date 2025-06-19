package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0631i extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.ui.graphics.V g;
    public final /* synthetic */ long h;
    public final /* synthetic */ long i;
    public final /* synthetic */ long j;
    public final /* synthetic */ long k;
    public final /* synthetic */ float l;
    public final /* synthetic */ androidx.compose.ui.window.r m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0631i(Function0 function0, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.ui.graphics.V v, long j, long j2, long j3, long j4, float f, androidx.compose.ui.window.r rVar, int i, int i2, int i3) {
        super(2);
        this.a = function0;
        this.b = dVar;
        this.c = qVar;
        this.d = dVar2;
        this.e = dVar3;
        this.f = dVar4;
        this.g = v;
        this.h = j;
        this.i = j2;
        this.j = j3;
        this.k = j4;
        this.l = f;
        this.m = rVar;
        this.n = i;
        this.o = i2;
        this.p = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.n | 1);
        int iH2 = C0776c.H(this.o);
        androidx.compose.runtime.internal.d dVar = this.b;
        long j = this.k;
        int i = this.p;
        Z1.a(this.a, dVar, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, j, this.l, this.m, (InterfaceC0806l) obj, iH, iH2, i);
        return Unit.a;
    }
}
