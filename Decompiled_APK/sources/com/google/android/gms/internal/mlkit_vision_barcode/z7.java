package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.braze.C1483i;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class z7 {
    public static final void a(final boolean z, final com.quizlet.assembly.compose.modals.x xVar, Function1 function1, int i, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        int i4;
        Function1 function12;
        int i5;
        Function1 function13;
        int i6;
        Function1 function14;
        int i7;
        final Function1 function15;
        final int i8;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1897521645);
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.g(z) ? 4 : 2);
        } else {
            i4 = i2;
        }
        int i9 = i4 | (c0814p.h(xVar) ? 32 : 16);
        int i10 = i3 & 4;
        if (i10 != 0) {
            i5 = i9 | 384;
            function12 = function1;
        } else {
            function12 = function1;
            i5 = i9 | (c0814p.h(function12) ? 256 : 128);
        }
        int i11 = i5 | 1024;
        if ((i11 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            i8 = i;
            function15 = function12;
        } else {
            c0814p.S();
            int i12 = i2 & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i12 == 0 || c0814p.w()) {
                if (i10 != 0) {
                    c0814p.X(1302676956);
                    Object objI = c0814p.I();
                    if (objI == v) {
                        objI = new C4237k(25);
                        c0814p.i0(objI);
                    }
                    function13 = (Function1) objI;
                    c0814p.p(false);
                } else {
                    function13 = function12;
                }
                Function1 function16 = function13;
                i6 = i11 & (-7169);
                function14 = function16;
                i7 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i7 = i;
                i6 = i11 & (-7169);
                function14 = function12;
            }
            c0814p.q();
            Object[] objArr = new Object[0];
            c0814p.X(1302680770);
            boolean z2 = (i6 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new C1483i(z, 14);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI2, c0814p, 0, 6);
            AbstractC3579a6.d(null, androidx.compose.runtime.internal.e.e(-366896431, new com.quizlet.features.notes.modals.e(i7, interfaceC0773a0, 0), c0814p), com.quizlet.features.notes.modals.c.a, androidx.compose.runtime.internal.e.e(1494165484, new com.quizlet.features.infra.basestudy.ui.h(xVar, function14, interfaceC0773a0, 1), c0814p), null, 0, false, c0814p, 3504, ContentType.LIVE);
            function15 = function14;
            i8 = i7;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.notes.modals.d
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int i13 = i8;
                    z7.a(z, xVar, function15, i13, (InterfaceC0806l) obj, iH, i3);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(androidx.glance.p pVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1060451148);
        if ((((c0814p.f(pVar) ? 4 : 2) | i | 16 | (c0814p.f(function1) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.glance.appwidget.lazy.c cVar = androidx.glance.appwidget.lazy.c.a;
            androidx.glance.layout.c cVar2 = new androidx.glance.layout.c(0, 1);
            ArrayList arrayList = new ArrayList();
            function1.invoke(new androidx.glance.appwidget.lazy.h(arrayList));
            androidx.compose.runtime.internal.d dVar = new androidx.compose.runtime.internal.d(true, 1748368075, new androidx.compose.foundation.contextmenu.i(27, arrayList, cVar2));
            c0814p.Y(578571862);
            c0814p.Y(-548224868);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(cVar);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.appwidget.lazy.d.b);
            C0776c.E(c0814p, new androidx.glance.layout.a(0), androidx.glance.appwidget.lazy.d.c);
            dVar.invoke(c0814p, 0);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.i(pVar, function1, i, 26);
        }
    }

    public static final void c(boolean z, com.quizlet.assembly.compose.modals.x modalState, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.compose.modals.x xVar;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-367478198);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            xVar = modalState;
        } else {
            xVar = modalState;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(xVar, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1760599599, new com.quizlet.assembly.compose.listitems.v(z, modalState, function1), c0814p), c0814p, 1572872 | ((i2 >> 3) & 14), 62);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.f(z, xVar, function1, i);
        }
    }

    public static final void d(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, boolean z) {
        androidx.compose.ui.q qVar2;
        int i3;
        long J;
        androidx.compose.ui.q qVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-641290556);
        int i4 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.g(z) ? 256 : 128);
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 = i4 | 3072;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p.f(qVar2) ? 2048 : 1024);
        }
        int i6 = i3 | (c0814p.h(function0) ? 16384 : 8192);
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i5 != 0) {
                qVar2 = nVar;
            }
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar2, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float f = com.quizlet.themes.m.l;
            if (z) {
                c0814p.X(-226496083);
                J = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).J();
                c0814p.p(false);
            } else {
                c0814p.X(-226403672);
                J = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).P0;
                c0814p.p(false);
            }
            C0555x c0555xA = AbstractC0460p.a(J, f);
            mVar.c();
            float f2 = com.quizlet.ui.resources.designsystem.generated.f.h;
            androidx.compose.ui.q qVarH = AbstractC0460p.h(qVarC, c0555xA.a, c0555xA.b, androidx.compose.foundation.shape.e.a(f2));
            mVar.c();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.draw.g.c(qVarH, androidx.compose.foundation.shape.e.a(f2));
            c0814p.X(-1808409269);
            boolean z2 = (57344 & i6) == 16384;
            Object objI = c0814p.I();
            if (z2 || objI == v) {
                objI = new com.braze.support.u(17, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarC2, false, null, (Function0) objI, 7);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC3, c0912h4);
            mVar.s();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f3);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            androidx.compose.ui.q qVarG = qVarU.g(new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarG);
            c0814p.b0();
            androidx.compose.ui.q qVar4 = qVar2;
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0776c.E(c0814p, qVarC4, c0912h4);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).j;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i6 & 14, 0, 65530);
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).p;
            long jF = ((com.quizlet.themes.b) c0814p.j(b2)).b.f();
            mVar.w();
            androidx.compose.material3.Q4.b(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p, (i6 >> 3) & 14, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarP = com.quizlet.ui.resources.icons.d.p(c0814p);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, DefinitionKt.NO_Float_VALUE, 11);
            mVar.h();
            androidx.compose.ui.q qVarA = androidx.compose.ui.draw.g.a(androidx.compose.foundation.layout.K0.k(qVarY, com.quizlet.ui.resources.designsystem.generated.h.g), z ? 1.0f : DefinitionKt.NO_Float_VALUE);
            String strD = AbstractC3106b5.d(c0814p, R.string.checked_a11y);
            long jF2 = ((com.quizlet.themes.b) c0814p.j(b2)).b.f();
            AbstractC0460p.c(bVarP, strD, qVarA, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(jF2, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jF2, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jF2), androidx.compose.ui.graphics.F.E(5))), c0814p, 0, 56);
            c0814p.p(true);
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.q(i, i2, qVar3, str, str2, function0, z);
        }
    }

    public static final void e(long j, androidx.glance.layout.c cVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2015416678);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            int i3 = i & 64;
            i2 |= c0814p.f(cVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.U(1110757559, Long.valueOf(j));
            androidx.glance.appwidget.lazy.e eVar = androidx.glance.appwidget.lazy.e.a;
            c0814p.Y(578571862);
            int i4 = i2 & 896;
            c0814p.Y(-548224868);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(eVar);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, Long.valueOf(j), androidx.glance.appwidget.lazy.d.d);
            C0776c.E(c0814p, cVar, androidx.glance.appwidget.lazy.d.e);
            dVar.invoke(c0814p, Integer.valueOf((i4 >> 6) & 14));
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material3.J1(j, cVar, dVar, i, 2);
        }
    }

    public static void f(AtomicLong atomicLong, long j) {
        long j2;
        do {
            j2 = atomicLong.get();
            if (j2 == Long.MAX_VALUE) {
                return;
            }
        } while (!atomicLong.compareAndSet(j2, g(j2, j)));
    }

    public static long g(long j, long j2) {
        long j3 = j + j2;
        if (j3 < 0) {
            return Long.MAX_VALUE;
        }
        return j3;
    }
}
