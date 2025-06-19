package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.o4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0697o4 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ androidx.compose.ui.layout.W b;
    public final /* synthetic */ androidx.compose.ui.layout.M c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Integer f;
    public final /* synthetic */ Integer g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0697o4(androidx.compose.ui.layout.W w, androidx.compose.ui.layout.W w2, androidx.compose.ui.layout.M m, int i, int i2, Integer num, Integer num2) {
        super(1);
        this.a = w;
        this.b = w2;
        this.c = m;
        this.d = i;
        this.e = i2;
        this.f = num;
        this.g = num2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        androidx.compose.ui.layout.W w = this.b;
        int i = this.e;
        androidx.compose.ui.layout.W w2 = this.a;
        if (w2 != null && w != null) {
            Integer num = this.f;
            Intrinsics.d(num);
            int iIntValue = num.intValue();
            Integer num2 = this.g;
            Intrinsics.d(num2);
            int iIntValue2 = num2.intValue();
            float f = iIntValue == iIntValue2 ? AbstractC0709q4.c : AbstractC0709q4.d;
            androidx.compose.ui.layout.M m = this.c;
            int iM0 = m.m0(androidx.compose.material3.tokens.u.a) + m.m0(f);
            int iJ0 = (m.j0(AbstractC0709q4.e) + w.b) - iIntValue;
            int i2 = w2.a;
            int i3 = this.d;
            int i4 = (i - iIntValue2) - iM0;
            androidx.compose.ui.layout.V.f(v, w2, (i3 - i2) / 2, i4);
            androidx.compose.ui.layout.V.f(v, w, (i3 - w.a) / 2, i4 - iJ0);
        } else if (w2 != null) {
            float f2 = AbstractC0709q4.a;
            androidx.compose.ui.layout.V.f(v, w2, 0, (i - w2.b) / 2);
        } else if (w != null) {
            float f3 = AbstractC0709q4.a;
            androidx.compose.ui.layout.V.f(v, w, 0, (i - w.b) / 2);
        }
        return Unit.a;
    }
}
