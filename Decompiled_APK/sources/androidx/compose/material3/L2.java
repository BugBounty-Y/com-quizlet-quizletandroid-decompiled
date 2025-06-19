package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class L2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ float c;
    public final /* synthetic */ androidx.compose.ui.layout.W d;
    public final /* synthetic */ int e;
    public final /* synthetic */ float f;
    public final /* synthetic */ float g;
    public final /* synthetic */ androidx.compose.ui.layout.W h;
    public final /* synthetic */ int i;
    public final /* synthetic */ float j;
    public final /* synthetic */ androidx.compose.ui.layout.W k;
    public final /* synthetic */ int l;
    public final /* synthetic */ float m;
    public final /* synthetic */ int n;
    public final /* synthetic */ androidx.compose.ui.layout.M o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L2(androidx.compose.ui.layout.W w, boolean z, float f, androidx.compose.ui.layout.W w2, int i, float f2, float f3, androidx.compose.ui.layout.W w3, int i2, float f4, androidx.compose.ui.layout.W w4, int i3, float f5, int i4, androidx.compose.ui.layout.M m) {
        super(1);
        this.a = w;
        this.b = z;
        this.c = f;
        this.d = w2;
        this.e = i;
        this.f = f2;
        this.g = f3;
        this.h = w3;
        this.i = i2;
        this.j = f4;
        this.k = w4;
        this.l = i3;
        this.m = f5;
        this.n = i4;
        this.o = m;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        float f = this.j;
        float f2 = this.g;
        androidx.compose.ui.layout.W w = this.a;
        if (w != null) {
            androidx.compose.ui.layout.V.f(v, w, (this.n - w.a) / 2, kotlin.math.c.b((f - this.o.m0(M2.e)) + f2));
        }
        if (this.b || this.c != DefinitionKt.NO_Float_VALUE) {
            androidx.compose.ui.layout.V.f(v, this.d, this.e, kotlin.math.c.b(this.f + f2));
        }
        androidx.compose.ui.layout.V.f(v, this.h, this.i, kotlin.math.c.b(f + f2));
        androidx.compose.ui.layout.V.f(v, this.k, this.l, kotlin.math.c.b(this.m + f2));
        return Unit.a;
    }
}
