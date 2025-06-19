package com.google.android.gms.internal.mlkit_vision_camera;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4090o;
import com.quizlet.assembly.compose.buttons.C4091p;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.buttons.InterfaceC4092q;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes2.dex */
public abstract class K1 {
    public static final void a(com.quizlet.features.paywall.state.c cVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function03;
        androidx.compose.ui.n nVar;
        C0814p c0814p;
        InterfaceC4092q c4091p;
        InterfaceC4092q c4091p2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(998819595);
        if ((i & 48) == 0) {
            i2 = ((i & 64) == 0 ? c0814p2.f(cVar) : c0814p2.h(cVar) ? 32 : 16) | i;
        } else {
            i2 = i;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function03 = function02;
            i2 |= c0814p2.h(function03) ? 2048 : 1024;
        } else {
            function03 = function02;
        }
        if ((i2 & 1169) == 1168 && c0814p2.x()) {
            c0814p2.Q();
        } else {
            String strC = cVar.c();
            C4097w c4097w = C4097w.a;
            C4076a c4076a = C4076a.j;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            boolean z = cVar instanceof com.quizlet.features.paywall.state.b;
            InterfaceC4092q interfaceC4092q = C4090o.a;
            if (z) {
                nVar = nVar2;
                long j = C0861v.f;
                c0814p = c0814p2;
                c4091p = new C4091p(AbstractC3409x1.h(new C0861v(j), new C0861v(C0861v.b(new com.quizlet.themes.b(false, 3).w(), 0.4f)), new C0861v(j)));
            } else {
                nVar = nVar2;
                c0814p = c0814p2;
                c4091p = interfaceC4092q;
            }
            int i3 = i2;
            C0814p c0814p3 = c0814p;
            W4.a(strC, qVarC, function0, false, c4076a, c4097w, c4091p, null, null, false, c0814p3, (i2 & 896) | 48, 904);
            c0814p2 = c0814p3;
            String strB = cVar.b();
            C4076a c4076a2 = C4076a.n;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            if (z) {
                long j2 = C0861v.f;
                c4091p2 = new C4091p(AbstractC3409x1.h(new C0861v(j2), new C0861v(C0861v.b(new com.quizlet.themes.b(false, 3).o(), 0.4f)), new C0861v(j2)));
            } else {
                c4091p2 = interfaceC4092q;
            }
            AbstractC3586b5.a(strB, qVarY, function03, false, c4076a2, c4097w, null, c4091p2, null, c0814p2, (i3 >> 3) & 896, 840);
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 24, cVar, function0, function02);
        }
    }

    public static final void b(com.quizlet.features.paywall.state.c cVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-847493856);
        if (((i | (c0814p.f(cVar) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC0460p.c(Z4.a(R.drawable.ic_union, c0814p, 0), null, androidx.compose.foundation.layout.K0.c(androidx.compose.ui.platform.N.G(nVar, "background_image"), 1.0f), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 432, 120);
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c, AbstractC0460p.r(c0814p), false, 14);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarU, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, f2, 5);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-636516566);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_quizlet_plus, c0814p, 0);
            c0814p.p(false);
            String strD = AbstractC3106b5.d(c0814p, R.string.quizlet_plus);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jO = ((com.quizlet.themes.b) c0814p.j(b)).o();
            AbstractC0460p.c(bVarA, strD, androidx.compose.foundation.layout.K0.k(nVar, 75), null, null, DefinitionKt.NO_Float_VALUE, new C0853m(jO, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jO, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jO), androidx.compose.ui.graphics.F.E(5))), c0814p, 384, 56);
            String strD2 = cVar.d();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b2)).d;
            mVar.s();
            Q4.b(strD2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(b)).o(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            String strA = cVar.a();
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b2)).n;
            mVar.q();
            Q4.b(strA, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(b)).o(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l2, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(cVar, qVar, i, 23);
        }
    }

    public static final void c(com.quizlet.features.paywall.state.c cVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1787055498);
        int i2 = (c0814p.f(cVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 10);
            c0814p.X(-169662578);
            int i3 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i4 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, 32 | i4), new C0416v0(C0380d.e(c0814p).k, i4));
            c0814p.p(false);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.U0.b(qVarY, c0374a), 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.d, androidx.compose.ui.b.n, c0814p, 54);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            int i6 = i2 << 3;
            a(cVar, function0, function02, c0814p, (i6 & 7168) | (i6 & ContentType.LONG_FORM_ON_DEMAND) | 6 | (i6 & 896));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 2, cVar, function0, function02);
        }
    }

    public static final void d(com.quizlet.features.paywall.state.c state, androidx.compose.ui.n nVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1029367351);
        if (((i | (c0814p2.f(state) ? 4 : 2) | 48 | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.h(function02) ? 2048 : 1024) | (c0814p2.h(function03) ? 16384 : 8192)) & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            long jL = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).L();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(nVar3, androidx.compose.runtime.internal.e.e(-951096179, new com.quizlet.explanations.questiondetail.ui.composables.m(14, function03), c0814p2), androidx.compose.runtime.internal.e.e(-758164978, new com.quizlet.assembly.compose.menu.l(state, function0, function02, 16), c0814p2), null, null, 0, jL, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1167594024, new com.quizlet.baseui.base.d(state, 5), c0814p2), c0814p, 805306806, 184);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(state, nVar2, function0, function02, function03, i, 5);
        }
    }

    public static final void e(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1165249541);
        if ((((c0814p.h(function0) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3691o6.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).A(), 0L, 0L, null, androidx.compose.runtime.internal.e.e(1979216368, new com.quizlet.explanations.questiondetail.ui.composables.m(15, function0), c0814p), null, null, c0814p, 196608, AdvertisementType.LIVE);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 4, function0);
        }
    }

    public static final C4986c f(io.reactivex.rxjava3.core.k kVar) {
        return kotlinx.coroutines.flow.e0.g(new kotlinx.coroutines.rx3.g(kVar, null));
    }

    public static com.jakewharton.rxbinding4.a g(InterfaceC4992i interfaceC4992i) {
        return new com.jakewharton.rxbinding4.a(new com.quizlet.quizletandroid.ui.studymodes.write.g(kotlin.coroutines.n.a, interfaceC4992i), 3);
    }

    public static String h(Class navigatorClass) {
        Intrinsics.checkNotNullParameter(navigatorClass, "navigatorClass");
        LinkedHashMap linkedHashMap = androidx.navigation.X.b;
        String strValue = (String) linkedHashMap.get(navigatorClass);
        if (strValue == null) {
            androidx.navigation.V v = (androidx.navigation.V) navigatorClass.getAnnotation(androidx.navigation.V.class);
            strValue = v != null ? v.value() : null;
            if (strValue == null || strValue.length() <= 0) {
                throw new IllegalArgumentException("No @Navigator.Name annotation found for ".concat(navigatorClass.getSimpleName()).toString());
            }
            linkedHashMap.put(navigatorClass, strValue);
        }
        Intrinsics.d(strValue);
        return strValue;
    }
}
