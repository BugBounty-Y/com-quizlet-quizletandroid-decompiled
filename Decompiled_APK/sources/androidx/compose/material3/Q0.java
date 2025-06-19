package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class Q0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Long a;
    public final /* synthetic */ long b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ AbstractC0655t f;
    public final /* synthetic */ IntRange g;
    public final /* synthetic */ C0716s0 h;
    public final /* synthetic */ InterfaceC0764y3 i;
    public final /* synthetic */ C0699p0 j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q0(Long l, long j, int i, Function1 function1, Function1 function12, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, int i2) {
        super(2);
        this.a = l;
        this.b = j;
        this.c = i;
        this.d = function1;
        this.e = function12;
        this.f = abstractC0655t;
        this.g = intRange;
        this.h = c0716s0;
        this.i = interfaceC0764y3;
        this.j = c0699p0;
        this.k = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.k | 1);
        InterfaceC0764y3 interfaceC0764y3 = this.i;
        C0699p0 c0699p0 = this.j;
        Z0.k(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, interfaceC0764y3, c0699p0, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
