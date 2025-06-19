package androidx.compose.foundation.lazy.grid;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class g extends kotlin.jvm.internal.r implements Function2 {
    public static final g b = new g(2, 0);
    public static final g c = new g(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                return new C0427b(AbstractC3173j0.d(1));
            default:
                A a = (A) obj2;
                return kotlin.collections.B.j(Integer.valueOf(a.b.a()), Integer.valueOf(a.b.b()));
        }
    }
}
