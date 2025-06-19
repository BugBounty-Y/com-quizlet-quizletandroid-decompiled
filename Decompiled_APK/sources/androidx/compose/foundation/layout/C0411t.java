package androidx.compose.foundation.layout;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0411t extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.ui.layout.M d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0411t(androidx.compose.ui.layout.W w, androidx.compose.ui.layout.J j, androidx.compose.ui.layout.M m, int i, int i2, C0415v c0415v) {
        super(1);
        this.e = w;
        this.f = j;
        this.d = m;
        this.b = i;
        this.c = i2;
        this.g = c0415v;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AbstractC0409s.b((androidx.compose.ui.layout.V) obj, (androidx.compose.ui.layout.W) this.e, (androidx.compose.ui.layout.J) this.f, this.d.getLayoutDirection(), this.b, this.c, ((C0415v) this.g).a);
                break;
            default:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                androidx.compose.ui.layout.W[] wArr = (androidx.compose.ui.layout.W[]) this.e;
                int length = wArr.length;
                int i = 0;
                int i2 = 0;
                while (i < length) {
                    androidx.compose.ui.layout.W w = wArr[i];
                    int i3 = i2 + 1;
                    Intrinsics.d(w);
                    Object objG = w.G();
                    D0 d0 = objG instanceof D0 ? (D0) objG : null;
                    androidx.compose.ui.unit.k layoutDirection = this.d.getLayoutDirection();
                    B b = (B) this.f;
                    b.getClass();
                    AbstractC0382e abstractC0382e = d0 != null ? d0.c : null;
                    int i4 = this.b;
                    androidx.compose.ui.layout.V.d(v, w, abstractC0382e != null ? abstractC0382e.g(i4 - w.a, layoutDirection, w, this.c) : b.b.a(0, i4 - w.a, layoutDirection), ((int[]) this.g)[i2]);
                    i++;
                    i2 = i3;
                }
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0411t(androidx.compose.ui.layout.W[] wArr, B b, int i, int i2, androidx.compose.ui.layout.M m, int[] iArr) {
        super(1);
        this.e = wArr;
        this.f = b;
        this.b = i;
        this.c = i2;
        this.d = m;
        this.g = iArr;
    }
}
