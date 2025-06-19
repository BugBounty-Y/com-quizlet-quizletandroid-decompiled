package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class P5 {
    public static final void a(Object key, Function0 onItemViewed, com.quizlet.ui.compose.util.a aVar, androidx.compose.runtime.internal.d content, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(onItemViewed, "onItemViewed");
        Intrinsics.checkNotNullParameter(content, "content");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1512471421);
        int i2 = (c0814p.h(key) ? 4 : 2) | i | (c0814p.h(onItemViewed) ? 32 : 16) | (c0814p.f(aVar) ? 256 : 128);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            content.invoke(c0814p, 6);
            if (aVar != null) {
                c(key, onItemViewed, aVar, c0814p, i2 & 1022);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(key, onItemViewed, aVar, content, i, 9);
        }
    }

    public static final long b(int i, int i2) {
        return (i2 & 4294967295L) | (i << 32);
    }

    public static final void c(Object key, Function0 onItemViewed, com.quizlet.ui.compose.util.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(onItemViewed, "onItemViewed");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-63125922);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(key) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onItemViewed) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(aVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else if (aVar != null) {
            if (aVar.a) {
                c0814p.X(2014873723);
                Object objI = c0814p.I();
                androidx.compose.runtime.V v = C0804k.a;
                if (objI == v) {
                    objI = C0776c.q(new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(10, aVar, key));
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                if (((Boolean) ((androidx.compose.runtime.W0) objI).getValue()).booleanValue()) {
                    c0814p.X(2014886521);
                    boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
                    Object objI2 = c0814p.I();
                    if (z || objI2 == v) {
                        objI2 = new com.quizlet.ui.compose.util.c(onItemViewed, null);
                        c0814p.i0(objI2);
                    }
                    c0814p.p(false);
                    C0776c.f(c0814p, onItemViewed, (Function2) objI2);
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 27, key, onItemViewed, aVar);
        }
    }

    public static final void d(com.quizlet.features.infra.models.folders.c cVar, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(143350129);
        int i2 = i | (c0814p2.h(cVar) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.themes.m.g.b();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j);
            long j = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).f;
            c0814p2.X(1099860945);
            boolean zH = ((i2 & 896) == 256) | c0814p2.h(cVar);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.composable.i(function1, cVar, 0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar, dVarA, j, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(385442935, new androidx.navigation.compose.o(21, cVar, function1), c0814p2), c0814p, ((i2 >> 3) & 14) | 100663296, 728);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 25, cVar, qVar, function1);
        }
    }

    public static final long e(long j) {
        return (Math.round(androidx.compose.ui.geometry.b.e(j)) & 4294967295L) | (Math.round(androidx.compose.ui.geometry.b.d(j)) << 32);
    }
}
