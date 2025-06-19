package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function1;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0247i0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(C0247i0 c0247i0, int i) {
        super(1);
        this.a = i;
        this.b = c0247i0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                long jLongValue = ((Number) obj).longValue();
                C0247i0 c0247i0 = this.b;
                long j = jLongValue - c0247i0.m;
                c0247i0.m = jLongValue;
                long jC = kotlin.math.c.c(j / c0247i0.q);
                androidx.collection.G g = c0247i0.n;
                int i = g.b;
                int i2 = 0;
                if (i != 0) {
                    Object[] objArr = g.a;
                    for (int i3 = 0; i3 < i; i3++) {
                        X x = (X) objArr[i3];
                        C0247i0.U(c0247i0, x, jC);
                        x.c = true;
                    }
                    E0 e0 = c0247i0.f;
                    if (e0 != null) {
                        e0.q();
                    }
                    int i4 = g.b;
                    Object[] objArr2 = g.a;
                    IntRange intRangeH = kotlin.ranges.l.h(0, i4);
                    int i5 = intRangeH.a;
                    int i6 = intRangeH.b;
                    if (i5 <= i6) {
                        while (true) {
                            objArr2[i5 - i2] = objArr2[i5];
                            if (((X) objArr2[i5]).c) {
                                i2++;
                            }
                            if (i5 != i6) {
                                i5++;
                            }
                        }
                    }
                    C4930v.o(objArr2, null, i4 - i2, i4);
                    g.b -= i2;
                }
                X x2 = c0247i0.o;
                if (x2 != null) {
                    x2.g = c0247i0.g;
                    C0247i0.U(c0247i0, x2, jC);
                    c0247i0.d0(x2.d);
                    if (x2.d == 1.0f) {
                        c0247i0.o = null;
                    }
                    c0247i0.c0();
                }
                break;
            default:
                this.b.m = ((Number) obj).longValue();
                break;
        }
        return Unit.a;
    }
}
