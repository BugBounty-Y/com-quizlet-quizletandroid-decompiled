package androidx.compose.material3;

import androidx.compose.material3.internal.C0654s;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.ranges.IntRange;

/* renamed from: androidx.compose.material3.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0737u0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0585a1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0737u0(C0585a1 c0585a1, int i) {
        super(1);
        this.a = i;
        this.b = c0585a1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                int i = ((C0615f1) obj).a;
                C0585a1 c0585a1 = this.b;
                Long lB = c0585a1.b();
                if (lB != null) {
                    c0585a1.c(c0585a1.b.a(lB.longValue()).e);
                }
                ((androidx.compose.runtime.L0) c0585a1.f).setValue(new C0615f1(i));
                return Unit.a;
            case 1:
                Long l = (Long) obj;
                C0585a1 c0585a12 = this.b;
                InterfaceC0773a0 interfaceC0773a0 = c0585a12.e;
                if (l != null) {
                    C0654s c0654sC = c0585a12.b.c(l.longValue());
                    IntRange intRange = c0585a12.a;
                    int i2 = c0654sC.a;
                    if (!intRange.b(i2)) {
                        throw new IllegalArgumentException(("The provided date's year (" + i2 + ") is out of the years range of " + intRange + '.').toString());
                    }
                    ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(c0654sC);
                } else {
                    ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(null);
                }
                return Unit.a;
            default:
                this.b.c(((Number) obj).longValue());
                return Unit.a;
        }
    }
}
