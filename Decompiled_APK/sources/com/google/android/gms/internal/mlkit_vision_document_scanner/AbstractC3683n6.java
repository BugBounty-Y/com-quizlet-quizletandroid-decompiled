package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3683n6;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.n6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3683n6 {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v1 */
    /* JADX WARN: Type inference failed for: r12v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r12v3 */
    public static final void a(androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        Object obj;
        boolean z;
        int i2;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar2;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        AbstractC0809m0 abstractC0809m0;
        Unit unit;
        kotlinx.coroutines.flow.d0 d0Var;
        ?? r12;
        androidx.compose.ui.q qVar3;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar3;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar4;
        androidx.compose.ui.q qVar4;
        C0814p c0814p2;
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(1499622301);
        int i3 = i | 6 | (c0814p3.h(function0) ? 32 : 16) | (c0814p3.h(function02) ? 256 : 128) | (c0814p3.h(function03) ? 2048 : 1024) | (c0814p3.h(function04) ? 16384 : 8192) | (c0814p3.h(function05) ? 131072 : 65536) | 524288;
        if ((i3 & 599187) == 599186 && c0814p3.x()) {
            c0814p3.Q();
            qVar4 = qVar;
            bVar4 = bVar;
            c0814p2 = c0814p3;
        } else {
            c0814p3.S();
            int i4 = i & 1;
            Object obj2 = C0804k.a;
            if (i4 == 0 || c0814p3.w()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                c0814p3.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                obj = obj2;
                z = false;
                Object objE = AbstractC3417z1.e(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p3);
                C0814p c0814p4 = c0814p3;
                c0814p4.p(false);
                c0814p4.p(false);
                i2 = i3 & (-3670017);
                bVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b) objE;
                qVar2 = nVar;
                c0814p = c0814p4;
            } else {
                c0814p3.Q();
                obj = obj2;
                z = false;
                bVar2 = bVar;
                i2 = i3 & (-3670017);
                qVar2 = qVar;
                c0814p = c0814p3;
            }
            c0814p.q();
            AbstractC0809m0 abstractC0809m02 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m02);
            Unit unit2 = Unit.a;
            c0814p.X(1406649967);
            boolean zH = c0814p.h(j) | c0814p.h(bVar2);
            Object objI = c0814p.I();
            if (zH || objI == obj) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.w(j, bVar2, null);
                c0814p.i0(objI);
            }
            c0814p.p(z);
            C0776c.f(c0814p, unit2, (Function2) objI);
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) bVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(iVar.i, c0814p);
            kotlinx.coroutines.flow.d0 d0Var2 = iVar.j;
            c0814p.X(1406660070);
            boolean z2 = ((i2 & 458752) == 131072) | ((57344 & i2) == 16384) | ((i2 & 7168) == 2048) | ((i2 & 896) == 256) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI2 = c0814p.I();
            if (z2 || objI2 == obj) {
                abstractC0809m0 = abstractC0809m02;
                unit = unit2;
                d0Var = d0Var2;
                r12 = 0;
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.x xVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.x(function04, function03, function02, function0, function05, null);
                c0814p.i0(xVar);
                objI2 = xVar;
            } else {
                abstractC0809m0 = abstractC0809m02;
                d0Var = d0Var2;
                unit = unit2;
                r12 = 0;
            }
            c0814p.p(r12);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j2) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.t(interfaceC0773a0D, j2, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(r12);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(r12);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "learn_round_summary");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, r12);
            int i5 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.q qVar5 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.q) interfaceC0773a0G.getValue();
            if (Intrinsics.b(qVar5, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.o.a)) {
                c0814p.X(88928193);
                bVar3 = bVar2;
                qVar3 = qVar2;
                AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
                c0814p.p(r12);
            } else {
                qVar3 = qVar2;
                bVar3 = bVar2;
                if (qVar5 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m) {
                    c0814p.X(88931100);
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m) qVar5;
                    c0814p.X(88932928);
                    boolean zH2 = c0814p.h(bVar3);
                    Object objI4 = c0814p.I();
                    if (zH2 || objI4 == obj) {
                        objI4 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, bVar3, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/checkpoint/data/LearnRoundSummaryEvent;)V", 0, 29);
                        c0814p.i0(objI4);
                    }
                    c0814p.p(r12);
                    AbstractC3730t6.a(mVar, null, (Function1) ((kotlin.reflect.f) objI4), c0814p, r12);
                    c0814p.p(r12);
                } else if (qVar5 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n) {
                    c0814p.X(88936193);
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n nVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n) qVar5;
                    c0814p.X(88938176);
                    boolean zH3 = c0814p.h(bVar3);
                    Object objI5 = c0814p.I();
                    if (zH3 || objI5 == obj) {
                        objI5 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, bVar3, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/checkpoint/data/LearnRoundSummaryEvent;)V", 0, 0);
                        c0814p.i0(objI5);
                    }
                    c0814p.p(r12);
                    AbstractC3714r6.a(nVar2, null, (Function1) ((kotlin.reflect.f) objI5), c0814p, r12);
                    c0814p.p(r12);
                } else {
                    if (!(qVar5 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p)) {
                        throw com.google.android.gms.measurement.internal.Z.j(88925784, c0814p, r12);
                    }
                    c0814p.X(88941150);
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p pVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p) qVar5;
                    c0814p.X(88943040);
                    boolean zH4 = c0814p.h(bVar3);
                    Object objI6 = c0814p.I();
                    if (zH4 || objI6 == obj) {
                        objI6 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, bVar3, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/checkpoint/data/LearnRoundSummaryEvent;)V", 0, 1);
                        c0814p.i0(objI6);
                    }
                    c0814p.p(r12);
                    AbstractC3738u6.a(pVar, null, (Function1) ((kotlin.reflect.f) objI6), c0814p, 0, 2);
                    c0814p.p(r12);
                }
            }
            c0814p.p(true);
            bVar4 = bVar3;
            qVar4 = qVar3;
            c0814p2 = c0814p;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(qVar4, function0, function02, function03, function04, function05, bVar4, i, 5);
        }
    }

    public static final void b(androidx.compose.ui.n nVar, final long j, final androidx.compose.ui.graphics.painter.b bVar, final Function0 function0, C0374a c0374a, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.n nVar2;
        C0374a c0374a2;
        final androidx.compose.ui.n nVar3;
        final C0374a c0374a3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1541108798);
        if (((i | 6 | (c0814p.e(j) ? 32 : 16) | (c0814p.h(bVar) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | 8192) & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            c0374a3 = c0374a;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                c0814p.X(-1784204838);
                C0416v0 c0416v0B = androidx.compose.material3.W4.b(c0814p);
                WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
                C0374a c0374a4 = new C0374a(c0416v0B, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
                c0814p.p(false);
                c0374a2 = c0374a4;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                c0374a2 = c0374a;
            }
            c0814p.q();
            C0374a c0374a5 = c0374a2;
            androidx.compose.ui.n nVar4 = nVar2;
            androidx.compose.material3.D.b(com.quizlet.assembly.compose.toolbars.d.a, nVar4, androidx.compose.runtime.internal.e.e(1010328743, new com.quizlet.assembly.compose.toolbars.b(bVar, function0, 1), c0814p), null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, c0374a5, androidx.compose.material3.W4.c(j, j, 0L, 0L, c0814p, 28), null, c0814p, 438, 312);
            c0814p = c0814p;
            nVar3 = nVar4;
            c0374a3 = c0374a5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(j, bVar, function0, c0374a3, i) { // from class: com.quizlet.assembly.compose.toolbars.g
                public final /* synthetic */ long b;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b c;
                public final /* synthetic */ Function0 d;
                public final /* synthetic */ C0374a e;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function0 function02 = this.d;
                    C0374a c0374a6 = this.e;
                    AbstractC3683n6.b(this.a, this.b, this.c, function02, c0374a6, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
