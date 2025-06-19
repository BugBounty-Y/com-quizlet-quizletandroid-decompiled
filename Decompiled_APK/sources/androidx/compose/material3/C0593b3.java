package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.b3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0593b3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ androidx.compose.ui.layout.W c;
    public final /* synthetic */ androidx.compose.ui.layout.W d;
    public final /* synthetic */ androidx.compose.ui.layout.W e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;
    public final /* synthetic */ androidx.compose.ui.layout.W g;
    public final /* synthetic */ androidx.compose.ui.layout.W h;
    public final /* synthetic */ androidx.compose.ui.layout.W i;
    public final /* synthetic */ androidx.compose.ui.layout.W j;
    public final /* synthetic */ androidx.compose.ui.layout.W k;
    public final /* synthetic */ C0599c3 l;
    public final /* synthetic */ androidx.compose.ui.layout.M m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0593b3(int i, int i2, androidx.compose.ui.layout.W w, androidx.compose.ui.layout.W w2, androidx.compose.ui.layout.W w3, androidx.compose.ui.layout.W w4, androidx.compose.ui.layout.W w5, androidx.compose.ui.layout.W w6, androidx.compose.ui.layout.W w7, androidx.compose.ui.layout.W w8, androidx.compose.ui.layout.W w9, C0599c3 c0599c3, androidx.compose.ui.layout.M m) {
        super(1);
        this.a = i;
        this.b = i2;
        this.c = w;
        this.d = w2;
        this.e = w3;
        this.f = w4;
        this.g = w5;
        this.h = w6;
        this.i = w7;
        this.j = w8;
        this.k = w9;
        this.l = c0599c3;
        this.m = m;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        float f;
        int iRound;
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        C0599c3 c0599c3 = this.l;
        float f2 = c0599c3.c;
        androidx.compose.ui.layout.M m = this.m;
        float fA = m.a();
        androidx.compose.ui.unit.k layoutDirection = m.getLayoutDirection();
        float f3 = AbstractC0587a3.a;
        androidx.compose.ui.layout.V.e(v, this.j, 0L);
        float f4 = androidx.compose.material3.internal.Y.b;
        androidx.compose.ui.layout.W w = this.k;
        int i = this.a - (w != null ? w.b : 0);
        androidx.compose.foundation.layout.A0 a0 = c0599c3.d;
        int iB = kotlin.math.c.b(a0.b * fA);
        int iB2 = kotlin.math.c.b(AbstractC0382e.k(a0, layoutDirection) * fA);
        float f5 = androidx.compose.material3.internal.Y.c * fA;
        androidx.compose.ui.layout.W w2 = this.c;
        if (w2 != null) {
            androidx.compose.ui.layout.V.f(v, w2, 0, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i - w2.b) / 2.0f)));
        }
        boolean z = c0599c3.b;
        androidx.compose.ui.layout.W w3 = this.h;
        if (w3 != null) {
            if (z) {
                f = 2.0f;
                iRound = Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i - w3.b) / 2.0f));
            } else {
                f = 2.0f;
                iRound = iB;
            }
            androidx.compose.ui.layout.V.f(v, w3, kotlin.math.c.b(w2 == null ? 0.0f : (1 - f2) * (w2.a - f5)) + iB2, V5.d(iRound, f2, -(w3.b / 2)));
        } else {
            f = 2.0f;
        }
        androidx.compose.ui.layout.W w4 = this.e;
        if (w4 != null) {
            androidx.compose.ui.layout.V.f(v, w4, w2 != null ? w2.a : 0, AbstractC0587a3.f(z, i, iB, w3, w4));
        }
        int i2 = (w2 != null ? w2.a : 0) + (w4 != null ? w4.a : 0);
        androidx.compose.ui.layout.W w5 = this.g;
        androidx.compose.ui.layout.V.f(v, w5, i2, AbstractC0587a3.f(z, i, iB, w3, w5));
        androidx.compose.ui.layout.W w6 = this.i;
        if (w6 != null) {
            androidx.compose.ui.layout.V.f(v, w6, i2, AbstractC0587a3.f(z, i, iB, w3, w6));
        }
        int i3 = this.b;
        androidx.compose.ui.layout.W w7 = this.d;
        androidx.compose.ui.layout.W w8 = this.f;
        if (w8 != null) {
            androidx.compose.ui.layout.V.f(v, w8, (i3 - (w7 != null ? w7.a : 0)) - w8.a, AbstractC0587a3.f(z, i, iB, w3, w8));
        }
        if (w7 != null) {
            androidx.compose.ui.layout.V.f(v, w7, i3 - w7.a, Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i - w7.b) / f)));
        }
        if (w != null) {
            androidx.compose.ui.layout.V.f(v, w, 0, i);
        }
        return Unit.a;
    }
}
