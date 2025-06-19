package androidx.compose.foundation.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F0(V0 v0, int i, androidx.compose.ui.layout.W w, int i2, androidx.compose.ui.layout.M m) {
        super(1);
        this.d = v0;
        this.b = i;
        this.e = w;
        this.c = i2;
        this.f = m;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                androidx.compose.ui.layout.W[] wArr = (androidx.compose.ui.layout.W[]) this.d;
                int length = wArr.length;
                int i = 0;
                int i2 = 0;
                while (i < length) {
                    androidx.compose.ui.layout.W w = wArr[i];
                    int i3 = i2 + 1;
                    Intrinsics.d(w);
                    Object objG = w.G();
                    D0 d0 = objG instanceof D0 ? (D0) objG : null;
                    G0 g0 = (G0) this.e;
                    g0.getClass();
                    AbstractC0382e abstractC0382e = d0 != null ? d0.c : null;
                    int i4 = this.b;
                    androidx.compose.ui.layout.V.d(v, w, ((int[]) this.f)[i2], abstractC0382e != null ? abstractC0382e.g(i4 - w.b, androidx.compose.ui.unit.k.a, w, this.c) : g0.b.a(0, i4 - w.b));
                    i++;
                    i2 = i3;
                }
                break;
            default:
                ?? r0 = ((V0) this.d).o;
                androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) this.e;
                androidx.compose.ui.layout.V.e((androidx.compose.ui.layout.V) obj, w2, ((androidx.compose.ui.unit.h) r0.invoke(new androidx.compose.ui.unit.j(R5.a(this.b - w2.a, this.c - w2.b)), ((androidx.compose.ui.layout.M) this.f).getLayoutDirection())).a);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F0(androidx.compose.ui.layout.W[] wArr, G0 g0, int i, int i2, int[] iArr) {
        super(1);
        this.d = wArr;
        this.e = g0;
        this.b = i;
        this.c = i2;
        this.f = iArr;
    }
}
