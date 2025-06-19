package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.core.L0;
import androidx.compose.animation.core.M0;
import androidx.compose.animation.core.V0;
import androidx.compose.material3.C0736u;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class V {
    public static final L0 a;
    public static final C0253l0 b;
    public static final C0253l0 c;
    public static final C0253l0 d;

    static {
        C0229c c0229c = C0229c.i;
        C0229c c0229c2 = C0229c.j;
        L0 l0 = M0.a;
        a = new L0(c0229c, c0229c2);
        b = AbstractC0240f.q(5, null);
        Object obj = V0.a;
        c = AbstractC0240f.q(1, new androidx.compose.ui.unit.h(P5.b(1, 1)));
        d = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
    }

    public static final a0 a(androidx.compose.animation.core.D d2, androidx.compose.ui.i iVar, Function1 function1) {
        return new a0(new q0((c0) null, (o0) null, new I(d2, iVar, function1), (E) null, (LinkedHashMap) null, 59));
    }

    public static a0 b(K0 k0, int i) {
        androidx.compose.ui.h hVar = androidx.compose.ui.b.j;
        int i2 = 1;
        androidx.compose.animation.core.D dQ = k0;
        if ((i & 1) != 0) {
            Object obj = V0.a;
            dQ = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
        }
        int i3 = i & 2;
        androidx.compose.ui.h hVar2 = androidx.compose.ui.b.l;
        androidx.compose.ui.h hVar3 = i3 != 0 ? hVar2 : hVar;
        return a(dQ, Intrinsics.b(hVar3, hVar) ? androidx.compose.ui.b.b : Intrinsics.b(hVar3, hVar2) ? androidx.compose.ui.b.h : androidx.compose.ui.b.e, new C0229c(i2, 15));
    }

    public static a0 c(K0 k0, int i) {
        androidx.compose.animation.core.D dQ = k0;
        if ((i & 1) != 0) {
            dQ = AbstractC0240f.q(5, null);
        }
        return new a0(new q0(new c0((i & 2) != 0 ? DefinitionKt.NO_Float_VALUE : 0.6f, dQ), (o0) null, (I) null, (E) null, (LinkedHashMap) null, 62));
    }

    public static b0 d(K0 k0, int i) {
        androidx.compose.animation.core.D dQ = k0;
        if ((i & 1) != 0) {
            dQ = AbstractC0240f.q(5, null);
        }
        return new b0(new q0(new c0(DefinitionKt.NO_Float_VALUE, dQ), (o0) null, (I) null, (E) null, (LinkedHashMap) null, 62));
    }

    public static final b0 e(androidx.compose.animation.core.D d2, androidx.compose.ui.i iVar, Function1 function1) {
        return new b0(new q0((c0) null, (o0) null, new I(d2, iVar, function1), (E) null, (LinkedHashMap) null, 59));
    }

    public static b0 f(K0 k0, int i) {
        androidx.compose.ui.h hVar = androidx.compose.ui.b.j;
        int i2 = 1;
        androidx.compose.animation.core.D dQ = k0;
        if ((i & 1) != 0) {
            Object obj = V0.a;
            dQ = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
        }
        int i3 = i & 2;
        androidx.compose.ui.h hVar2 = androidx.compose.ui.b.l;
        androidx.compose.ui.h hVar3 = i3 != 0 ? hVar2 : hVar;
        return e(dQ, Intrinsics.b(hVar3, hVar) ? androidx.compose.ui.b.b : Intrinsics.b(hVar3, hVar2) ? androidx.compose.ui.b.h : androidx.compose.ui.b.e, new C0229c(i2, 17));
    }

    public static final a0 g(androidx.compose.animation.core.D d2, Function1 function1) {
        return new a0(new q0((c0) null, new o0(d2, new U(0, function1)), (I) null, (E) null, (LinkedHashMap) null, 61));
    }

    public static a0 h(int i) {
        Function1 function1 = C0736u.i;
        Object obj = V0.a;
        C0253l0 c0253l0Q = AbstractC0240f.q(1, new androidx.compose.ui.unit.h(P5.b(1, 1)));
        if ((i & 2) != 0) {
            function1 = C0229c.m;
        }
        return g(c0253l0Q, function1);
    }

    public static final b0 i(androidx.compose.animation.core.D d2, Function1 function1) {
        return new b0(new q0((c0) null, new o0(d2, new U(1, function1)), (I) null, (E) null, (LinkedHashMap) null, 61));
    }

    public static b0 j(int i, Function1 function1) {
        Object obj = V0.a;
        C0253l0 c0253l0Q = AbstractC0240f.q(1, new androidx.compose.ui.unit.h(P5.b(1, 1)));
        if ((i & 2) != 0) {
            function1 = C0229c.n;
        }
        return i(c0253l0Q, function1);
    }
}
