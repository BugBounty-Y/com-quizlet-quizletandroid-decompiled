package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.q2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0707q2 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ F3 c;
    public final /* synthetic */ float d;
    public final /* synthetic */ androidx.compose.ui.graphics.V e;
    public final /* synthetic */ long f;
    public final /* synthetic */ long g;
    public final /* synthetic */ float h;
    public final /* synthetic */ long i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ C0602d0 k;
    public final /* synthetic */ B2 l;
    public final /* synthetic */ androidx.compose.runtime.internal.d m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0707q2(Function0 function0, androidx.compose.ui.q qVar, F3 f3, float f, androidx.compose.ui.graphics.V v, long j, long j2, float f2, long j3, androidx.compose.runtime.internal.d dVar, C0602d0 c0602d0, B2 b2, androidx.compose.runtime.internal.d dVar2, int i) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = f3;
        this.d = f;
        this.e = v;
        this.f = j;
        this.g = j2;
        this.h = f2;
        this.i = j3;
        this.j = dVar;
        this.k = c0602d0;
        this.l = b2;
        this.m = dVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1);
        androidx.compose.runtime.internal.d dVar = this.m;
        androidx.compose.runtime.internal.d dVar2 = this.j;
        C0602d0 c0602d0 = this.k;
        A2.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, dVar2, c0602d0, this.l, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
