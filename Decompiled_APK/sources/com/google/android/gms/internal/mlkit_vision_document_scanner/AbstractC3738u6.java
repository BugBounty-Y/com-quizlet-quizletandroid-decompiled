package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.C4896o;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.u6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3738u6 {
    public static final void a(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p uiState, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Function1 function12;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(49893409);
        int i4 = i | (c0814p2.h(uiState) ? 4 : 2);
        int i5 = i4 | 48;
        int i6 = i2 & 4;
        if (i6 != 0) {
            i3 = i4 | 432;
            function12 = function1;
        } else {
            function12 = function1;
            i3 = i5 | (c0814p2.h(function12) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            if (i6 != 0) {
                c0814p2.X(607007393);
                Object objI = c0814p2.I();
                if (objI == v) {
                    objI = new com.quizlet.quizletandroid.ui.login.z(12);
                    c0814p2.i0(objI);
                }
                function12 = (Function1) objI;
                c0814p2.p(false);
            }
            c0814p2.X(607008774);
            Object objI2 = c0814p2.I();
            Object obj = objI2;
            if (objI2 == v) {
                androidx.compose.animation.core.T t = new androidx.compose.animation.core.T(Boolean.FALSE);
                ((androidx.compose.runtime.L0) t.d).setValue(Boolean.TRUE);
                c0814p2.i0(t);
                obj = t;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(nVar, "learn_round_summary_simplified"), null, null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(1218111154, new com.quizlet.assembly.compose.input.h(uiState, function12, (androidx.compose.animation.core.T) obj, 24), c0814p2), c0814p, 805306368, 446);
            qVar2 = nVar;
        }
        Function1 function13 = function12;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, i2, 19, (Object) uiState, (Object) qVar2, (InterfaceC4938g) function13);
        }
    }

    public static final C4885d b(com.quizlet.data.connectivity.a aVar, Function0 lazyConnected, Function0 lazyNotConnected) {
        io.reactivex.rxjava3.core.i w;
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(lazyConnected, "lazyConnected");
        Intrinsics.checkNotNullParameter(lazyNotConnected, "lazyNotConnected");
        com.braze.support.u uVar = new com.braze.support.u(6, lazyConnected);
        com.braze.support.u uVar2 = new com.braze.support.u(7, lazyNotConnected);
        com.quizlet.remote.connectivity.a aVar2 = ((com.quizlet.remote.connectivity.b) aVar).a;
        com.quizlet.data.repository.searchexplanations.c cVar = new com.quizlet.data.repository.searchexplanations.c(13, uVar, uVar2);
        io.reactivex.rxjava3.core.k kVar = aVar2.a;
        kVar.getClass();
        int i = io.reactivex.rxjava3.core.e.a;
        io.reactivex.rxjava3.internal.functions.d.a(i, "bufferSize");
        if (kVar instanceof io.reactivex.rxjava3.operators.c) {
            Object obj = ((io.reactivex.rxjava3.operators.c) kVar).get();
            w = obj == null ? io.reactivex.rxjava3.internal.operators.observable.E.a : new io.reactivex.rxjava3.internal.operators.mixed.b(3, obj, cVar);
        } else {
            w = new io.reactivex.rxjava3.internal.operators.observable.W(kVar, cVar, i, 2);
        }
        C4896o c4896o = new C4896o(new io.reactivex.rxjava3.internal.operators.mixed.b(w));
        Intrinsics.checkNotNullExpressionValue(c4896o, "refCount(...)");
        C4885d c4885dJ = c4896o.j();
        Intrinsics.checkNotNullExpressionValue(c4885dJ, "firstOrError(...)");
        return c4885dJ;
    }
}
