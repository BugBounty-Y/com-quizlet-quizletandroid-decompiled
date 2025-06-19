package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class C0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Long a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ AbstractC0655t e;
    public final /* synthetic */ IntRange f;
    public final /* synthetic */ C0716s0 g;
    public final /* synthetic */ InterfaceC0764y3 h;
    public final /* synthetic */ C0699p0 i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0(Long l, long j, Function1 function1, Function1 function12, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0, int i) {
        super(2);
        this.a = l;
        this.b = j;
        this.c = function1;
        this.d = function12;
        this.e = abstractC0655t;
        this.f = intRange;
        this.g = c0716s0;
        this.h = interfaceC0764y3;
        this.i = c0699p0;
        this.j = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        InterfaceC0764y3 interfaceC0764y3 = this.h;
        C0699p0 c0699p0 = this.i;
        Z0.j(this.a, this.b, this.c, this.d, this.e, this.f, this.g, interfaceC0764y3, c0699p0, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
