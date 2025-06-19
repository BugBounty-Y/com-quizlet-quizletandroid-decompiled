package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class K1 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ androidx.compose.ui.layout.W b;
    public final /* synthetic */ int c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ int e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;
    public final /* synthetic */ androidx.compose.ui.layout.W g;
    public final /* synthetic */ androidx.compose.ui.layout.W h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K1(androidx.compose.ui.layout.W w, androidx.compose.ui.layout.W w2, int i, boolean z, int i2, androidx.compose.ui.layout.W w3, androidx.compose.ui.layout.W w4, androidx.compose.ui.layout.W w5, int i3, int i4, int i5) {
        super(1);
        this.a = w;
        this.b = w2;
        this.c = i;
        this.d = z;
        this.e = i2;
        this.f = w3;
        this.g = w4;
        this.h = w5;
        this.i = i3;
        this.j = i4;
        this.k = i5;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        int i = this.c;
        int i2 = this.i;
        int iRound = this.e;
        boolean z = this.d;
        androidx.compose.ui.layout.W w = this.a;
        if (w != null) {
            androidx.compose.ui.layout.V.f(v, w, i, z ? iRound : Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i2 - w.b) / 2.0f)));
        }
        androidx.compose.ui.layout.W w2 = this.b;
        if (w2 != null) {
            androidx.compose.ui.layout.V.f(v, w2, (this.j - this.k) - w2.a, z ? iRound : Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i2 - w2.b) / 2.0f)));
        }
        float f = androidx.compose.material3.internal.Y.b;
        int i3 = i + (w != null ? w.a : 0);
        androidx.compose.ui.layout.W w3 = this.h;
        androidx.compose.ui.layout.W w4 = this.g;
        androidx.compose.ui.layout.W w5 = this.f;
        if (!z) {
            iRound = Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i2 - (((w5 != null ? w5.b : 0) + (w4 != null ? w4.b : 0)) + (w3 != null ? w3.b : 0))) / 2.0f));
        }
        if (w4 != null) {
            androidx.compose.ui.layout.V.f(v, w4, i3, iRound);
        }
        int i4 = iRound + (w4 != null ? w4.b : 0);
        if (w5 != null) {
            androidx.compose.ui.layout.V.f(v, w5, i3, i4);
        }
        int i5 = i4 + (w5 != null ? w5.b : 0);
        if (w3 != null) {
            androidx.compose.ui.layout.V.f(v, w3, i3, i5);
        }
        return Unit.a;
    }
}
