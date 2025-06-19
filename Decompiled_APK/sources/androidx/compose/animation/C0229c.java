package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0262q;
import androidx.compose.animation.core.C0265s;
import androidx.compose.ui.graphics.C0861v;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0229c extends kotlin.jvm.internal.r implements Function1 {
    public static final C0229c b = new C0229c(1, 0);
    public static final C0229c c = new C0229c(1, 1);
    public static final C0229c d = new C0229c(1, 2);
    public static final C0229c e = new C0229c(1, 3);
    public static final C0229c f = new C0229c(1, 4);
    public static final C0229c g = new C0229c(1, 5);
    public static final C0229c h = new C0229c(1, 6);
    public static final C0229c i = new C0229c(1, 7);
    public static final C0229c j = new C0229c(1, 8);
    public static final C0229c k = new C0229c(1, 9);
    public static final C0229c l = new C0229c(1, 10);
    public static final C0229c m = new C0229c(1, 11);
    public static final C0229c n = new C0229c(1, 12);
    public static final C0229c o = new C0229c(1, 13);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0229c(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return obj;
            case 1:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                return bool;
            case 2:
                Boolean bool2 = (Boolean) obj;
                bool2.booleanValue();
                return bool2;
            case 3:
                Boolean bool3 = (Boolean) obj;
                bool3.booleanValue();
                return bool3;
            case 4:
                Boolean bool4 = (Boolean) obj;
                bool4.booleanValue();
                return bool4;
            case 5:
                long jA = C0861v.a(((C0861v) obj).a, androidx.compose.ui.graphics.colorspace.d.t);
                return new C0265s(C0861v.d(jA), C0861v.h(jA), C0861v.g(jA), C0861v.e(jA));
            case 6:
                return obj;
            case 7:
                long j2 = ((androidx.compose.ui.graphics.Z) obj).a;
                return new C0262q(androidx.compose.ui.graphics.Z.b(j2), androidx.compose.ui.graphics.Z.c(j2));
            case 8:
                C0262q c0262q = (C0262q) obj;
                return new androidx.compose.ui.graphics.Z(androidx.compose.ui.graphics.F.i(c0262q.a, c0262q.b));
            case 9:
                return AbstractC0240f.q(7, null);
            case 10:
                long j3 = ((androidx.compose.ui.unit.j) obj).a;
                return new androidx.compose.ui.unit.j(R5.a(0, 0));
            case 11:
                return Integer.valueOf((-((Number) obj).intValue()) / 2);
            case 12:
                return Integer.valueOf((-((Number) obj).intValue()) / 2);
            case 13:
                return V.c;
            case 14:
                return new androidx.compose.ui.unit.j(R5.a(0, (int) (((androidx.compose.ui.unit.j) obj).a & 4294967295L)));
            case 15:
                return new androidx.compose.ui.unit.j(R5.a((int) (((androidx.compose.ui.unit.j) obj).a >> 32), 0));
            case 16:
                return new androidx.compose.ui.unit.j(R5.a(0, (int) (((androidx.compose.ui.unit.j) obj).a & 4294967295L)));
            default:
                return new androidx.compose.ui.unit.j(R5.a((int) (((androidx.compose.ui.unit.j) obj).a >> 32), 0));
        }
    }
}
