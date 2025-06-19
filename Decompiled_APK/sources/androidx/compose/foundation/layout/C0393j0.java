package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import java.util.WeakHashMap;

/* renamed from: androidx.compose.foundation.layout.j0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0393j0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public static final C0393j0 b = new C0393j0(3, 0);
    public static final C0393j0 c = new C0393j0(3, 1);
    public static final C0393j0 d = new C0393j0(3, 2);
    public static final C0393j0 e = new C0393j0(3, 3);
    public static final C0393j0 f = new C0393j0(3, 4);
    public static final C0393j0 g = new C0393j0(3, 5);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0393j0(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        androidx.compose.runtime.V v = C0804k.a;
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).z(((Number) obj3).intValue()));
            case 1:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).b(((Number) obj3).intValue()));
            case 2:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).X(((Number) obj3).intValue()));
            case 3:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).x(((Number) obj3).intValue()));
            case 4:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).x(((Number) obj3).intValue()));
            case 5:
                ((Number) obj2).intValue();
                return Integer.valueOf(((androidx.compose.ui.layout.J) obj).X(((Number) obj3).intValue()));
            case 6:
                ((Number) obj3).intValue();
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(359872873);
                WeakHashMap weakHashMap = S0.w;
                S0 s0E = C0380d.e(c0814p);
                boolean zF = c0814p.f(s0E);
                Object objI = c0814p.I();
                if (zF || objI == v) {
                    objI = new C0405p0(s0E.c);
                    c0814p.i0(objI);
                }
                C0405p0 c0405p0 = (C0405p0) objI;
                c0814p.p(false);
                return c0405p0;
            default:
                ((Number) obj3).intValue();
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(359872873);
                WeakHashMap weakHashMap2 = S0.w;
                S0 s0E2 = C0380d.e(c0814p2);
                boolean zF2 = c0814p2.f(s0E2);
                Object objI2 = c0814p2.I();
                if (zF2 || objI2 == v) {
                    objI2 = new C0405p0(s0E2.k);
                    c0814p2.i0(objI2);
                }
                C0405p0 c0405p02 = (C0405p0) objI2;
                c0814p2.p(false);
                return c0405p02;
        }
    }
}
