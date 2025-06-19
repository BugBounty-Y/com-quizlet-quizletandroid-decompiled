package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class V0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ InterfaceC0764y3 d;
    public final /* synthetic */ AbstractC0655t e;
    public final /* synthetic */ IntRange f;
    public final /* synthetic */ C0699p0 g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V0(androidx.compose.ui.q qVar, long j, Function1 function1, InterfaceC0764y3 interfaceC0764y3, AbstractC0655t abstractC0655t, IntRange intRange, C0699p0 c0699p0, int i) {
        super(2);
        this.a = qVar;
        this.b = j;
        this.c = function1;
        this.d = interfaceC0764y3;
        this.e = abstractC0655t;
        this.f = intRange;
        this.g = c0699p0;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        IntRange intRange = this.f;
        C0699p0 c0699p0 = this.g;
        Z0.m(this.a, this.b, this.c, this.d, this.e, intRange, c0699p0, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
