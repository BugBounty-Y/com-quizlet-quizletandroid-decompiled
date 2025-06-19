package androidx.compose.animation;

import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0287n extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W[] a;
    public final /* synthetic */ C0288o b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0287n(androidx.compose.ui.layout.W[] wArr, C0288o c0288o, int i, int i2) {
        super(1);
        this.a = wArr;
        this.b = c0288o;
        this.c = i;
        this.d = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        for (androidx.compose.ui.layout.W w : this.a) {
            if (w != null) {
                long jA = this.b.a.b.a(R5.a(w.a, w.b), R5.a(this.c, this.d), androidx.compose.ui.unit.k.a);
                androidx.compose.ui.layout.V.d(v, w, (int) (jA >> 32), (int) (jA & 4294967295L));
            }
        }
        return Unit.a;
    }
}
