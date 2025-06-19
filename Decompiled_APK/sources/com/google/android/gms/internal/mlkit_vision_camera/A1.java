package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3777z5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A1 {
    public static final void a(Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-175556253);
        int i2 = i | (c0814p.h(function1) ? 4 : 2);
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.q();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarC, f, com.quizlet.ui.resources.designsystem.generated.j.i);
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarV, c0374a);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarB);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            String strD = AbstractC3106b5.d(c0814p, R.string.yes);
            c0814p.X(1834829178);
            int i4 = i2 & 14;
            boolean z = i4 == 4;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(25, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            W4.a(strD, qVarC3, (Function0) objI, false, null, null, null, null, null, false, c0814p, 48, 1016);
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.no);
            c0814p.X(1834835611);
            boolean z2 = i4 == 4;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(26, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p = c0814p;
            Y4.b(strD2, qVarC4, (Function0) objI2, false, null, null, 0L, 0L, null, null, null, c0814p, 48, 0, 4088);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.l(function1, i, 6);
        }
    }

    public static final void b(androidx.compose.foundation.layout.z0 z0Var, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1989879944);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(z0Var) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarT = AbstractC0382e.t(nVar, z0Var);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarT);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m.g.s();
            Q4.b(AbstractC3106b5.d(c0814p, R.string.onboarding_flashcards_screen_title), AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).e, c0814p, 0, 0, 65532);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.t(z0Var, i, 2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:42:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(kotlin.jvm.functions.Function0 r20, kotlin.jvm.functions.Function1 r21, androidx.compose.ui.n r22, androidx.compose.runtime.InterfaceC0806l r23, int r24, int r25) {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.A1.c(kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.ui.n, androidx.compose.runtime.l, int, int):void");
    }

    public static final void d(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2123894510);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            C0380d c0380d = AbstractC0398m.b;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0380d, androidx.compose.ui.b.j, c0814p, 6);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.skip);
            com.quizlet.themes.m.g.s();
            function02 = function0;
            AbstractC3777z5.a(strD, AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), null, null, null, function02, c0814p, (i2 << 15) & 458752, 28);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 3, function02);
        }
    }

    public static final void e(int i, int i2) {
        if (i < 0 || i >= i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static final void f(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static final void g(int i, int i2, int i3) {
        if (i < 0 || i2 > i3) {
            StringBuilder sbW = android.support.v4.media.session.a.w("fromIndex: ", i, ", toIndex: ", ", size: ", i2);
            sbW.append(i3);
            throw new IndexOutOfBoundsException(sbW.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("fromIndex: ", i, " > toIndex: ", i2));
        }
    }

    public static androidx.lifecycle.w0 h(Class modelClass) throws IllegalAccessException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        try {
            Object objNewInstance = modelClass.getDeclaredConstructor(null).newInstance(null);
            Intrinsics.d(objNewInstance);
            return (androidx.lifecycle.w0) objNewInstance;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e);
        } catch (InstantiationException e2) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e2);
        } catch (NoSuchMethodException e3) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e3);
        }
    }
}
