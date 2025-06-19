package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0409s;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3543u4;
import com.quizlet.data.connectivity.NetworkOfflineError;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.x6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3762x6 {
    public static final void a(com.quizlet.learn.ui.g gVar, Function1 onEvent, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(onEvent, "onEvent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1648106531);
        int i2 = (c0814p.h(gVar) ? 4 : 2) | i | (c0814p.h(onEvent) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else if (gVar != null) {
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-306722053);
            int i4 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean z = i4 == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.login.intro.ui.k(21, onEvent);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(-306717546);
            boolean z2 = i4 == 32;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.login.intro.ui.k(22, onEvent);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            AbstractC3543u4.a(gVar, true, null, function0, (Function0) objI2, null, c0814p, (i2 & 14) | 56, 36);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(gVar, onEvent, qVar, i, 3);
        }
    }

    public static final void b(org.slf4j.b bVar, Throwable error, String nonOfflineErrorMessage) {
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        Intrinsics.checkNotNullParameter(error, "error");
        Intrinsics.checkNotNullParameter(nonOfflineErrorMessage, "nonOfflineErrorMessage");
        if (error instanceof NetworkOfflineError) {
            bVar.j("No network connection", error);
        } else {
            bVar.j(nonOfflineErrorMessage, error);
        }
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g c(io.reactivex.rxjava3.core.p pVar, org.slf4j.b logger, String nonOfflineErrorMessage) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(nonOfflineErrorMessage, "nonOfflineErrorMessage");
        com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(logger, false, nonOfflineErrorMessage, 14);
        pVar.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVar = new io.reactivex.rxjava3.internal.operators.single.g(pVar, bVar, 2);
        Intrinsics.checkNotNullExpressionValue(gVar, "onErrorResumeNext(...)");
        return gVar;
    }
}
