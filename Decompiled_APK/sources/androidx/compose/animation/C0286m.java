package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.V0;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0286m extends kotlin.jvm.internal.r implements Function2 {
    public static final C0286m b = new C0286m(2, 0);
    public static final C0286m c = new C0286m(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0286m(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                long j = ((androidx.compose.ui.unit.j) obj).a;
                long j2 = ((androidx.compose.ui.unit.j) obj2).a;
                Object obj3 = V0.a;
                return AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
            default:
                O o = (O) obj2;
                return Boolean.valueOf(((O) obj) == o && o == O.c);
        }
    }
}
