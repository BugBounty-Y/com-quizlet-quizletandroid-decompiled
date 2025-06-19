package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.appcompat.app.ExecutorC0060p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0393j0;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.material3.Q4;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.v2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3402v2 {
    public static final void a(Function0 selectedAnswer, Function1 onSelectAnswer, Function0 onNextQuestion, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(androidx.compose.foundation.layout.D.a, "<this>");
        Intrinsics.checkNotNullParameter(selectedAnswer, "selectedAnswer");
        Intrinsics.checkNotNullParameter(onSelectAnswer, "onSelectAnswer");
        Intrinsics.checkNotNullParameter(onNextQuestion, "onNextQuestion");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1653587805);
        if ((i & 48) == 0) {
            i2 = (c0814p.h(selectedAnswer) ? 32 : 16) | i;
        } else {
            i2 = i;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onSelectAnswer) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(onNextQuestion) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9361) == 9360 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object[] objArr = new Object[0];
            c0814p.X(-2140926427);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (z || objI == obj) {
                objI = new com.braze.support.u(26, selectedAnswer);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-2140923497);
            boolean zF = c0814p.f(interfaceC0773a0);
            Object objI2 = c0814p.I();
            if (zF || objI2 == obj) {
                objI2 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a0, 6);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            androidx.compose.runtime.H0 h0 = (androidx.compose.runtime.H0) L4.d(objArr2, null, (Function0) objI2, c0814p, 0, 6);
            c0814p.X(-2140921488);
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = new androidx.compose.ui.focus.p();
                c0814p.i0(objI3);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI3;
            c0814p.p(false);
            Unit unit = Unit.a;
            c0814p.X(-2140919500);
            Object objI4 = c0814p.I();
            if (objI4 == obj) {
                objI4 = new com.quizlet.features.practicetest.takingtest.u(pVar, null);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            androidx.compose.ui.q qVarA = androidx.compose.ui.a.a(androidx.compose.ui.platform.N.G(qVar, "practice_test_taking_test_mcq_written"), new C0393j0(3, 6));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarA);
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
            String str = (String) interfaceC0773a0.getValue();
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_taking_written_hint);
            c0814p.X(949704141);
            boolean zF2 = c0814p.f(interfaceC0773a0) | c0814p.f(h0) | ((i2 & 896) == 256);
            Object objI5 = c0814p.I();
            if (zF2 || objI5 == obj) {
                objI5 = new androidx.lifecycle.compose.d((Object) onSelectAnswer, interfaceC0773a0, (Object) h0, 15);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            AbstractC3745v5.a(str, null, (Function1) objI5, null, strD, 0, 10, 200, pVar, 6, 0, onNextQuestion, null, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, null, null, null, c0814p, 918552576, ((i2 >> 3) & 896) | 6, 0, 8382570);
            HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.o);
            com.quizlet.themes.m.g.u();
            Q4.b(AbstractC3106b5.c(R.string.practice_test_taking_written_character_count, new Object[]{Integer.valueOf(h0.i()), 200}, c0814p), AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) selectedAnswer, onSelectAnswer, onNextQuestion, qVar, i, 20);
        }
    }

    public static final String b(kotlin.reflect.c clazz, org.koin.core.qualifier.a aVar, org.koin.core.qualifier.a scopeQualifier) {
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Intrinsics.checkNotNullParameter(scopeQualifier, "scopeQualifier");
        return org.koin.ext.a.a(clazz) + ':' + (aVar != null ? aVar.a : "") + ':' + scopeQualifier;
    }

    public static final androidx.work.G c(androidx.work.B tracer, String label, ExecutorC0060p executor, Function0 block) {
        Intrinsics.checkNotNullParameter(tracer, "tracer");
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(block, "block");
        androidx.lifecycle.Y state = new androidx.lifecycle.Y(androidx.work.G.c);
        androidx.concurrent.futures.l future = Y5.b(new androidx.work.H(executor, tracer, label, block, state));
        Intrinsics.checkNotNullExpressionValue(future, "getFuture { completer ->…}\n            }\n        }");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(future, "future");
        androidx.work.G g = new androidx.work.G();
        g.a = future;
        return g;
    }
}
