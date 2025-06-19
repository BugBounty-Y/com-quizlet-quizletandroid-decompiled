package org.chromium.support_lib_boundary.util;

import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.compose.ui.viewinterop.k;
import androidx.glance.appwidget.action.g;
import androidx.glance.f;
import androidx.glance.layout.c;
import androidx.glance.layout.t;
import androidx.glance.n;
import androidx.glance.p;
import androidx.glance.s;
import androidx.navigation.compose.B;
import androidx.navigation.compose.x;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b;
import com.quizlet.quizletandroid.ui.widgets.j;
import com.quizlet.quizletandroid.ui.widgets.u;
import com.quizlet.quizletandroid.ui.widgets.ui.theme.d;
import com.quizlet.quizletandroid.ui.widgets.v;
import com.quizlet.themes.m;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final void a(androidx.appcompat.view.a linkProvider, n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(linkProvider, "linkProvider");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1964700312);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(linkProvider) : c0814p.h(linkProvider) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if (((i2 | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = n.a;
            p pVarB = AbstractC3207m7.b(AbstractC3180j7.b(AbstractC3332e.d(nVar), new androidx.glance.a(R.drawable.bg_widget)), g.a(linkProvider.b()));
            c0814p.X(-4752938);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(23);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            M7.a(AbstractC3340g.c(pVarB, (Function1) objI), c.c, j.b, c0814p, 384, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.widgets.p(linkProvider, nVar, i, 1);
        }
    }

    public static final void b(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1192210762);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.glance.a aVar = new androidx.glance.a(R.drawable.bg_shape_q_logo_quarter);
            f fVar = new f(new s(b.b(u.a, c0814p)));
            String strD = b.d(c0814p, R.string.q_logo);
            t tVar = new t(androidx.glance.unit.f.a);
            c0814p.X(-2050838472);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(24);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3189k7.c(aVar, strD, AbstractC3340g.c(tVar, (Function1) objI), 0, fVar, c0814p, 32768, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new x(i, 27);
        }
    }

    public static final void c(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1138145601);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            p pVarD = AbstractC3332e.f(AbstractC3332e.e(n.a), androidx.compose.ui.unit.g.a(((androidx.compose.ui.unit.g) c0814p.j(androidx.glance.j.a)).a) / 4).d(new androidx.glance.c(b.b(v.a, c0814p)));
            m.g.d();
            p pVarE = AbstractC3243q7.e(pVarD, com.quizlet.ui.resources.designsystem.generated.f.g);
            c0814p.X(-1238316576);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(25);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3328d.c(AbstractC3340g.c(pVarE, (Function1) objI), 1, 1, j.c, c0814p, 3072, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new x(i, 28);
        }
    }

    public static final void d(p pVar, InterfaceC0806l interfaceC0806l, int i) {
        p pVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1839887818);
        int i2 = (c0814p.f(pVar) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            pVar2 = pVar;
        } else {
            String strD = b.d(c0814p, R.string.no_recent_sets);
            ((d) c0814p.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
            pVar2 = pVar;
            AbstractC3401v1.a(strD, pVar2, d.e(c0814p), 0, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(pVar2, i, 15);
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, q qVar, Function1 fragmentNavigation, boolean z) {
        boolean z2;
        Intrinsics.checkNotNullParameter(fragmentNavigation, "fragmentNavigation");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(863902039);
        int i2 = (c0814p.h(fragmentNavigation) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16) | (c0814p.g(z) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            FillElement fillElement = K0.c;
            q qVarG = qVar.g(fillElement);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-386835969);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = com.quizlet.explanations.textbook.ui.composables.c.a;
                c0814p.i0(objI);
            }
            c0814p.p(false);
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) ((kotlin.reflect.f) objI);
            c0814p.X(-386834375);
            boolean z3 = (i2 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z3 || objI2 == v) {
                objI2 = new B(2, fragmentNavigation);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            k.d(cVar, fillElement, (Function1) objI2, c0814p, 54);
            c0814p.X(-386831820);
            if (z) {
                z2 = true;
                AbstractC0666j3.a(N.G(c0418x.a(nVar, androidx.compose.ui.b.e), "TextbookContentLoading"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).K(), DefinitionKt.NO_Float_VALUE, 0L, 0, c0814p, 0, 28);
            } else {
                z2 = true;
            }
            c0814p.p(false);
            c0814p.p(z2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.c(fragmentNavigation, qVar, z, i);
        }
    }

    public static Object f(Class cls, InvocationHandler invocationHandler) {
        if (invocationHandler == null) {
            return null;
        }
        return cls.cast(Proxy.newProxyInstance(a.class.getClassLoader(), new Class[]{cls}, invocationHandler));
    }
}
