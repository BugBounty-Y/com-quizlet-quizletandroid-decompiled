package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class K2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ androidx.compose.ui.layout.W b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;
    public final /* synthetic */ androidx.compose.ui.layout.W e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K2(androidx.compose.ui.layout.W w, androidx.compose.ui.layout.W w2, int i, int i2, androidx.compose.ui.layout.W w3, int i3, int i4, int i5, int i6) {
        super(1);
        this.a = w;
        this.b = w2;
        this.c = i;
        this.d = i2;
        this.e = w3;
        this.f = i3;
        this.g = i4;
        this.h = i5;
        this.i = i6;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        androidx.compose.ui.layout.W w = this.a;
        if (w != null) {
            androidx.compose.ui.layout.V.f(v, w, (this.h - w.a) / 2, (this.i - w.b) / 2);
        }
        androidx.compose.ui.layout.V.f(v, this.b, this.c, this.d);
        androidx.compose.ui.layout.V.f(v, this.e, this.f, this.g);
        return Unit.a;
    }
}
