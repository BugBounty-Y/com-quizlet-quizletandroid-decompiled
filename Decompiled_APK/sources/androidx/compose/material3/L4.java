package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class L4 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.ui.layout.W d;
    public final /* synthetic */ androidx.compose.ui.layout.W e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;
    public final /* synthetic */ androidx.compose.ui.layout.W g;
    public final /* synthetic */ androidx.compose.ui.layout.W h;
    public final /* synthetic */ androidx.compose.ui.layout.W i;
    public final /* synthetic */ androidx.compose.ui.layout.W j;
    public final /* synthetic */ androidx.compose.ui.layout.W k;
    public final /* synthetic */ N4 l;
    public final /* synthetic */ int m;
    public final /* synthetic */ androidx.compose.ui.layout.M n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L4(androidx.compose.ui.layout.W w, int i, int i2, androidx.compose.ui.layout.W w2, androidx.compose.ui.layout.W w3, androidx.compose.ui.layout.W w4, androidx.compose.ui.layout.W w5, androidx.compose.ui.layout.W w6, androidx.compose.ui.layout.W w7, androidx.compose.ui.layout.W w8, androidx.compose.ui.layout.W w9, N4 n4, int i3, androidx.compose.ui.layout.M m) {
        super(1);
        this.a = w;
        this.b = i;
        this.c = i2;
        this.d = w2;
        this.e = w3;
        this.f = w4;
        this.g = w5;
        this.h = w6;
        this.i = w7;
        this.j = w8;
        this.k = w9;
        this.l = n4;
        this.m = i3;
        this.n = m;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        androidx.compose.ui.layout.W w = this.d;
        androidx.compose.ui.layout.W w2 = this.j;
        androidx.compose.ui.layout.M m = this.n;
        androidx.compose.ui.layout.W w3 = this.k;
        androidx.compose.ui.layout.W w4 = this.i;
        androidx.compose.ui.layout.W w5 = this.h;
        androidx.compose.ui.layout.W w6 = this.g;
        androidx.compose.ui.layout.W w7 = this.f;
        androidx.compose.ui.layout.W w8 = this.e;
        int i = this.c;
        int i2 = this.b;
        N4 n4 = this.l;
        androidx.compose.ui.layout.W w9 = this.a;
        if (w9 != null) {
            boolean z = n4.a;
            int i3 = w9.b;
            int i4 = this.m + i3;
            float fA = m.a();
            float f = K4.a;
            androidx.compose.ui.layout.V.e(v, w2, 0L);
            float f2 = androidx.compose.material3.internal.Y.b;
            int i5 = i - (w3 != null ? w3.b : 0);
            if (w7 != null) {
                androidx.compose.ui.layout.V.f(v, w7, 0, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i5 - w7.b) / 2.0f)));
            }
            androidx.compose.ui.layout.V.f(v, w9, w7 != null ? w7.a : 0, (z ? Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i5 - w9.b) / 2.0f)) : kotlin.math.c.b(androidx.compose.material3.internal.Y.b * fA)) - kotlin.math.c.b((r3 - r5) * n4.b));
            if (w5 != null) {
                androidx.compose.ui.layout.V.f(v, w5, w7 != null ? w7.a : 0, i4);
            }
            int i6 = (w7 != null ? w7.a : 0) + (w5 != null ? w5.a : 0);
            androidx.compose.ui.layout.V.f(v, w, i6, i4);
            if (w8 != null) {
                androidx.compose.ui.layout.V.f(v, w8, i6, i4);
            }
            if (w4 != null) {
                androidx.compose.ui.layout.V.f(v, w4, (i2 - (w6 != null ? w6.a : 0)) - w4.a, i4);
            }
            if (w6 != null) {
                androidx.compose.ui.layout.V.f(v, w6, i2 - w6.a, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i5 - w6.b) / 2.0f)));
            }
            if (w3 != null) {
                androidx.compose.ui.layout.V.f(v, w3, 0, i5);
            }
        } else {
            boolean z2 = n4.a;
            float fA2 = m.a();
            float f3 = K4.a;
            androidx.compose.ui.layout.V.e(v, w2, 0L);
            float f4 = androidx.compose.material3.internal.Y.b;
            int i7 = i - (w3 != null ? w3.b : 0);
            int iB = kotlin.math.c.b(n4.c.b * fA2);
            if (w7 != null) {
                androidx.compose.ui.layout.V.f(v, w7, 0, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i7 - w7.b) / 2.0f)));
            }
            if (w5 != null) {
                androidx.compose.ui.layout.V.f(v, w5, w7 != null ? w7.a : 0, K4.e(z2, i7, iB, w5));
            }
            int i8 = (w7 != null ? w7.a : 0) + (w5 != null ? w5.a : 0);
            androidx.compose.ui.layout.V.f(v, w, i8, K4.e(z2, i7, iB, w));
            if (w8 != null) {
                androidx.compose.ui.layout.V.f(v, w8, i8, K4.e(z2, i7, iB, w8));
            }
            if (w4 != null) {
                androidx.compose.ui.layout.V.f(v, w4, (i2 - (w6 != null ? w6.a : 0)) - w4.a, K4.e(z2, i7, iB, w4));
            }
            if (w6 != null) {
                androidx.compose.ui.layout.V.f(v, w6, i2 - w6.a, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i7 - w6.b) / 2.0f)));
            }
            if (w3 != null) {
                androidx.compose.ui.layout.V.f(v, w3, 0, i7);
            }
        }
        return Unit.a;
    }
}
