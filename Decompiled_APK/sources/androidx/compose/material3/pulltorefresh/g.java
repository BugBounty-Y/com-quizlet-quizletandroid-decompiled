package androidx.compose.material3.pulltorefresh;

import android.graphics.Path;
import androidx.appcompat.app.L;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.C;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.d0;
import androidx.compose.animation.f0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0552u;
import androidx.compose.foundation.gestures.D;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.text.selection.C0527h;
import androidx.compose.material3.C0743v0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.O;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class g {
    public static final float a = (float) 2.5d;
    public static final float b = (float) 5.5d;
    public static final float c = 16;
    public static final float d = 40;
    public static final float e = 10;
    public static final float f = 5;
    public static final K0 g = AbstractC0240f.r(300, 0, C.d, 2);

    public static final void a(boolean z, Function0 function0, androidx.compose.ui.q qVar, q qVar2, androidx.compose.ui.i iVar, kotlin.jvm.functions.c cVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        kotlin.jvm.functions.c cVarE;
        androidx.compose.runtime.internal.d dVar2;
        kotlin.jvm.functions.c cVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1902956467);
        if (((i | (c0814p.g(z) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.f(qVar2) ? 2048 : 1024) | 196608) & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
            cVar2 = cVar;
            dVar2 = dVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                cVarE = androidx.compose.runtime.internal.e.e(1989171225, new C0527h(z, 2, qVar2), c0814p);
            } else {
                c0814p.Q();
                cVarE = cVar;
            }
            c0814p.q();
            androidx.compose.ui.q qVarG = qVar.g(new PullToRefreshElement(z, function0, qVar2, c.c));
            K kE = AbstractC0409s.e(iVar, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            dVar2 = dVar;
            dVar2.invoke(c0418x, c0814p, 54);
            cVarE.invoke(c0418x, c0814p, 54);
            c0814p.p(true);
            cVar2 = cVarE;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0743v0(z, function0, qVar, qVar2, iVar, cVar2, dVar2, i);
        }
    }

    public static final void b(Function0 function0, long j, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-569718810);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.e(j) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            V v = C0804k.a;
            Object obj = objI;
            if (objI == v) {
                C0850j c0850jH = F.h();
                c0850jH.f(1);
                c0814p.i0(c0850jH);
                obj = c0850jH;
            }
            O o = (O) obj;
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = C0776c.q(new androidx.compose.material.V(4, function0));
                c0814p.i0(objI2);
            }
            boolean z = true;
            W0 w0B = AbstractC0248j.b(((Number) ((W0) objI2).getValue()).floatValue(), g, null, null, c0814p, 48, 28);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i3 = i2 & 14;
            boolean z2 = i3 == 4;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == v) {
                objI3 = new D(7, function0);
                c0814p.i0(objI3);
            }
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(androidx.compose.ui.semantics.m.a(nVar, true, (Function1) objI3), c);
            boolean zF = (i3 == 4) | c0814p.f(w0B);
            if ((i2 & ContentType.LONG_FORM_ON_DEMAND) != 32) {
                z = false;
            }
            boolean zH = zF | z | c0814p.h(o);
            Object objI4 = c0814p.I();
            if (zH || objI4 == v) {
                C0552u c0552u = new C0552u(function0, w0B, j, o, 1);
                c0814p.i0(c0552u);
                objI4 = c0552u;
            }
            AbstractC0460p.b(qVarK, (Function1) objI4, c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material3.internal.V(function0, j, i);
        }
    }

    public static final void c(androidx.compose.ui.graphics.drawscope.d dVar, O o, androidx.compose.ui.geometry.c cVar, long j, float f2, f0 f0Var) {
        C0850j c0850j = (C0850j) o;
        c0850j.e();
        Path path = c0850j.a;
        path.moveTo(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        float f3 = e;
        float fC0 = dVar.c0(f3);
        float f4 = f0Var.c;
        path.lineTo((fC0 * f4) / 2, dVar.c0(f) * f4);
        path.lineTo(dVar.c0(f3) * f4, DefinitionKt.NO_Float_VALUE);
        float fD = (androidx.compose.ui.geometry.b.d(cVar.c()) + (Math.min(cVar.e(), cVar.d()) / 2.0f)) - ((dVar.c0(f3) * f4) / 2.0f);
        float fE = androidx.compose.ui.geometry.b.e(cVar.c());
        float f5 = a;
        c0850j.g(Q4.c(fD, fE - dVar.c0(f5)));
        float fC02 = f0Var.b - dVar.c0(f5);
        long jO0 = dVar.o0();
        com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
        long jR = cVarE0.r();
        cVarE0.o().e();
        try {
            ((L) cVarE0.b).O(jO0, fC02);
            androidx.compose.ui.graphics.drawscope.d.j(dVar, c0850j, j, f2, new androidx.compose.ui.graphics.drawscope.h(dVar.c0(f5), DefinitionKt.NO_Float_VALUE, 0, 0, 30), 48);
        } finally {
            d0.y(cVarE0, jR);
        }
    }
}
