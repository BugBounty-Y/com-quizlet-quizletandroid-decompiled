package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class P0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.d {
    public final /* synthetic */ Long a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ AbstractC0655t e;
    public final /* synthetic */ IntRange f;
    public final /* synthetic */ C0716s0 g;
    public final /* synthetic */ InterfaceC0764y3 h;
    public final /* synthetic */ C0699p0 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P0(Long l, long j, Function1 function1, Function1 function12, AbstractC0655t abstractC0655t, IntRange intRange, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0) {
        super(4);
        this.a = l;
        this.b = j;
        this.c = function1;
        this.d = function12;
        this.e = abstractC0655t;
        this.f = intRange;
        this.g = c0716s0;
        this.h = interfaceC0764y3;
        this.i = c0699p0;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        int i = ((C0615f1) obj2).a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj3;
        ((Number) obj4).intValue();
        if (i == 0) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            c0814p.X(-1870116901);
            Z0.j(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, c0814p, 0);
            c0814p.p(false);
        } else if (i == 1) {
            C0814p c0814p2 = (C0814p) interfaceC0806l;
            c0814p2.X(-1870098348);
            AbstractC0687n0.a(this.a, this.c, this.e, this.f, this.g, this.h, this.i, c0814p2, 0);
            c0814p2.p(false);
        } else {
            C0814p c0814p3 = (C0814p) interfaceC0806l;
            c0814p3.X(-2138080579);
            c0814p3.p(false);
        }
        return Unit.a;
    }
}
