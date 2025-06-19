package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.W0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0248j {
    public static final C0253l0 a = AbstractC0240f.q(7, null);

    static {
        Object obj = V0.a;
        new androidx.compose.ui.unit.e(0.1f);
        T4.a(0.5f, 0.5f);
        Q4.c(0.5f, 0.5f);
    }

    public static final W0 a(float f, K0 k0, InterfaceC0806l interfaceC0806l, int i) {
        return c(new androidx.compose.ui.unit.e(f), M0.c, k0, null, "DpAnimation", null, interfaceC0806l, (i << 3) & 896, 8);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [androidx.compose.animation.core.l0] */
    public static final W0 b(float f, K0 k0, String str, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        D d;
        int i3 = i2 & 2;
        ?? r1 = a;
        if (i3 != 0) {
            k0 = r1;
        }
        if ((i2 & 8) != 0) {
            str = "FloatAnimation";
        }
        String str2 = str;
        if ((i2 & 16) != 0) {
            function1 = null;
        }
        Function1 function12 = function1;
        if (k0 == r1) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            c0814p.X(1125598679);
            boolean zC = c0814p.c(0.01f);
            Object objI = c0814p.I();
            if (zC || objI == C0804k.a) {
                objI = AbstractC0240f.q(3, Float.valueOf(0.01f));
                c0814p.i0(objI);
            }
            c0814p.p(false);
            d = (C0253l0) objI;
        } else {
            C0814p c0814p2 = (C0814p) interfaceC0806l;
            c0814p2.X(1125708605);
            c0814p2.p(false);
            d = k0;
        }
        return c(Float.valueOf(f), M0.a, d, Float.valueOf(0.01f), str2, function12, interfaceC0806l, (i << 3) & 57344, 0);
    }

    public static final W0 c(Object obj, L0 l0, InterfaceC0256n interfaceC0256n, Float f, String str, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Object obj2 = C0804k.a;
        if ((i2 & 8) != 0) {
            f = null;
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (objI == obj2) {
            objI = C0776c.z(null);
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        Object objI2 = c0814p.I();
        if (objI2 == obj2) {
            objI2 = new C0238e(obj, l0, f);
            c0814p.i0(objI2);
        }
        C0238e c0238e = (C0238e) objI2;
        InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function1, c0814p);
        if (f != null && (interfaceC0256n instanceof C0253l0)) {
            C0253l0 c0253l0 = (C0253l0) interfaceC0256n;
            if (!Intrinsics.b(c0253l0.c, f)) {
                interfaceC0256n = new C0253l0(c0253l0.a, c0253l0.b, f);
            }
        }
        InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D(interfaceC0256n, c0814p);
        Object objI3 = c0814p.I();
        if (objI3 == obj2) {
            objI3 = D1.a(-1, 6, null);
            c0814p.i0(objI3);
        }
        kotlinx.coroutines.channels.l lVar = (kotlinx.coroutines.channels.l) objI3;
        boolean zH = c0814p.h(lVar) | ((((i & 14) ^ 6) > 4 && c0814p.h(obj)) || (i & 6) == 4);
        Object objI4 = c0814p.I();
        if (zH || objI4 == obj2) {
            objI4 = new C0242g(0, lVar, obj);
            c0814p.i0(objI4);
        }
        C0776c.i((Function0) objI4, c0814p);
        boolean zH2 = c0814p.h(lVar) | c0814p.h(c0238e) | c0814p.f(interfaceC0773a0D2) | c0814p.f(interfaceC0773a0D);
        Object objI5 = c0814p.I();
        if (zH2 || objI5 == obj2) {
            Object c0246i = new C0246i(lVar, c0238e, interfaceC0773a0D2, interfaceC0773a0D, null);
            c0814p.i0(c0246i);
            objI5 = c0246i;
        }
        C0776c.f(c0814p, lVar, (Function2) objI5);
        W0 w0 = (W0) interfaceC0773a0.getValue();
        return w0 == null ? c0238e.c : w0;
    }
}
