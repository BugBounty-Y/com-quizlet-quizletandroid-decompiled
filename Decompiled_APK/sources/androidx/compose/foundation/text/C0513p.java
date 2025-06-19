package androidx.compose.foundation.text;

import androidx.compose.ui.text.C0995g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0513p extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ N0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0513p(N0 n0, int i) {
        super(0);
        this.a = i;
        this.b = n0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        androidx.compose.ui.text.G g;
        switch (this.a) {
            case 0:
                N0 n0 = this.b;
                return Boolean.valueOf(n0 != null ? ((Boolean) new C0513p(n0, 2).invoke()).booleanValue() : false);
            case 1:
                N0 n02 = this.b;
                return Boolean.valueOf(n02 != null ? ((Boolean) new C0513p(n02, 2).invoke()).booleanValue() : false);
            default:
                N0 n03 = this.b;
                C0995g c0995g = n03.c;
                androidx.compose.ui.text.H h = (androidx.compose.ui.text.H) ((androidx.compose.runtime.L0) n03.b).getValue();
                return Boolean.valueOf(Intrinsics.b(c0995g, (h == null || (g = h.a) == null) ? null : g.a));
        }
    }
}
