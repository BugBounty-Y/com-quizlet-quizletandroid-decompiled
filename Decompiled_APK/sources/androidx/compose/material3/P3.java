package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class P3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ int b;
    public final /* synthetic */ androidx.compose.ui.layout.W c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P3(androidx.compose.ui.layout.W w, int i, androidx.compose.ui.layout.W w2, int i2, int i3, androidx.compose.ui.layout.W w3, int i4, int i5) {
        super(1);
        this.a = w;
        this.b = i;
        this.c = w2;
        this.d = i2;
        this.e = i3;
        this.f = w3;
        this.g = i4;
        this.h = i5;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        androidx.compose.ui.layout.V.f(v, this.a, 0, this.b);
        androidx.compose.ui.layout.W w = this.c;
        if (w != null) {
            androidx.compose.ui.layout.V.f(v, w, this.d, this.e);
        }
        androidx.compose.ui.layout.W w2 = this.f;
        if (w2 != null) {
            androidx.compose.ui.layout.V.f(v, w2, this.g, this.h);
        }
        return Unit.a;
    }
}
