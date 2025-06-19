package androidx.compose.foundation.contextmenu;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.D;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.text.L;
import androidx.compose.ui.window.y;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class q {
    public static final y a = new y(14);
    public static final c b;

    static {
        long j = C0861v.c;
        long j2 = C0861v.b;
        b = new c(j, j2, j2, C0861v.b(j2, 0.38f), C0861v.b(j2, 0.38f));
    }

    public static final void a(c cVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-921259293);
        if ((((c0814p.f(cVar) ? 4 : 2) | i | (c0814p.f(nVar) ? 32 : 16)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarU = AbstractC0460p.u(AbstractC0382e.w(AbstractC0382e.C(AbstractC0460p.f(androidx.compose.ui.draw.g.j(nVar, k.d, androidx.compose.foundation.shape.e.a(k.e), 28), cVar.a, F.a), 2), DefinitionKt.NO_Float_VALUE, k.i, 1), AbstractC0460p.r(c0814p), false, 14);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            dVar.invoke(D.a, c0814p, 54);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new i(cVar, dVar, i);
        }
    }

    public static final void b(String str, boolean z, c cVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(791018367);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(cVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(nVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(null) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.h hVar = k.f;
            C0380d c0380d = AbstractC0398m.a;
            float f = k.h;
            C0392j c0392jG = AbstractC0398m.g(f);
            boolean z2 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((458752 & i2) == 131072);
            Object objI = c0814p.I();
            if (z2 || objI == C0804k.a) {
                objI = new androidx.activity.compose.f(z, function0);
                c0814p.i0(objI);
            }
            androidx.compose.ui.q qVarC = K0.c(AbstractC0460p.l(nVar, z, str, (Function0) objI, 4), 1.0f);
            float f2 = k.a;
            float f3 = k.b;
            float f4 = k.c;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(K0.m(qVarC, f2, f4, f3, f4), f, DefinitionKt.NO_Float_VALUE, 2);
            G0 g0B = E0.b(c0392jG, hVar, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(554568909);
            c0814p.p(false);
            L l = new L(z ? cVar.b : cVar.d, k.j, k.k, null, null, k.m, k.g, k.l, 16613240);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException("invalid weight 1.0; must be greater than zero".toString());
            }
            AbstractC0484d0.b(str, new LayoutWeightElement(1.0f, true), l, null, 0, false, 1, 0, c0814p, (i2 & 14) | 1572864, 440);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new p(str, z, cVar, function0, i);
        }
    }

    public static final void c(h hVar, Function0 function0, c cVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function02;
        h hVar2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1447189339);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(hVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(nVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(cVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
            hVar2 = hVar;
        } else {
            function02 = function0;
            androidx.compose.ui.window.l.a(hVar, function02, a, androidx.compose.runtime.internal.e.e(795909757, new i(cVar, function1), c0814p), c0814p, (i2 & 14) | 3456 | (i2 & ContentType.LONG_FORM_ON_DEMAND), 0);
            hVar2 = hVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new b(hVar2, function02, cVar, function1, i);
        }
    }

    public static final void d(h hVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(712057293);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(hVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(nVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            boolean zF = c0814p.f((Configuration) c0814p.j(AndroidCompositionLocals_androidKt.a)) | c0814p.f(context);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                c cVar = b;
                long jC = cVar.a;
                TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(R.style.Widget.PopupMenu, new int[]{R.attr.colorBackground});
                int iA = F.A(jC);
                int color = typedArrayObtainStyledAttributes.getColor(0, iA);
                typedArrayObtainStyledAttributes.recycle();
                if (color != iA) {
                    jC = F.c(color);
                }
                long j = jC;
                TypedArray typedArrayObtainStyledAttributes2 = context.obtainStyledAttributes(R.style.TextAppearance.Widget.PopupMenu.Large, new int[]{R.attr.textColorPrimary});
                ColorStateList colorStateList = typedArrayObtainStyledAttributes2.getColorStateList(0);
                typedArrayObtainStyledAttributes2.recycle();
                long jC2 = cVar.b;
                int iA2 = F.A(jC2);
                Integer numValueOf = colorStateList != null ? Integer.valueOf(colorStateList.getColorForState(new int[]{R.attr.state_enabled}, iA2)) : null;
                if (numValueOf != null && numValueOf.intValue() != iA2) {
                    jC2 = F.c(numValueOf.intValue());
                }
                long j2 = jC2;
                long jC3 = cVar.d;
                int iA3 = F.A(jC3);
                Integer numValueOf2 = colorStateList != null ? Integer.valueOf(colorStateList.getColorForState(new int[]{-16842910}, iA3)) : null;
                if (numValueOf2 != null && numValueOf2.intValue() != iA3) {
                    jC3 = F.c(numValueOf2.intValue());
                }
                long j3 = jC3;
                c cVar2 = new c(j, j2, j2, j3, j3);
                c0814p.i0(cVar2);
                objI = cVar2;
            }
            c(hVar, function0, (c) objI, function1, c0814p, ((i2 << 3) & 57344) | (i2 & 1022));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new a(hVar, function0, function1, i);
        }
    }
}
