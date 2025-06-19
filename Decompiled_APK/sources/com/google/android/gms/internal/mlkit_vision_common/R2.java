package com.google.android.gms.internal.mlkit_vision_common;

import android.util.Log;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class R2 {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r8v3 */
    public static final void a(androidx.navigation.H navHostController, com.quizlet.features.settings.viewmodels.m mVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.navigation.H h;
        Object xVar;
        ?? r8;
        com.quizlet.features.settings.viewmodels.m mVar2;
        Intrinsics.checkNotNullParameter(navHostController, "navHostController");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2144420043);
        int i3 = (c0814p.h(navHostController) ? 4 : 2) | i | (c0814p.f(mVar) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            h = navHostController;
            mVar2 = mVar;
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            com.quizlet.themes.nighttheme.a aVar = (com.quizlet.themes.nighttheme.a) C0776c.l(((com.quizlet.features.settings.viewmodels.I) mVar).o, com.quizlet.themes.nighttheme.a.c, null, c0814p, 48, 2).getValue();
            c0814p.X(-2129134730);
            boolean zH = c0814p.h(navHostController);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                i2 = 32;
                com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, navHostController, androidx.navigation.H.class, "navigateUp", "navigateUp()Z", 8, 7);
                h = navHostController;
                c0814p.i0(cVar);
                objI = cVar;
            } else {
                h = navHostController;
                i2 = 32;
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(-2129132909);
            boolean z = (((i3 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > i2 && c0814p.h(mVar)) || (i3 & 48) == i2;
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                r8 = 0;
                mVar2 = mVar;
                xVar = new com.quizlet.features.settings.composables.x(1, mVar2, com.quizlet.features.settings.viewmodels.m.class, "onThemeSelected", "onThemeSelected(Lcom/quizlet/themes/nighttheme/NightThemeMode;)V", 0, 4);
                c0814p.i0(xVar);
            } else {
                r8 = 0;
                xVar = objI2;
                mVar2 = mVar;
            }
            c0814p.p(r8);
            b(aVar, function0, (Function1) ((kotlin.reflect.f) xVar), c0814p, r8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changetheme.b(h, mVar2, i, 1);
        }
    }

    public static final void b(com.quizlet.themes.nighttheme.a aVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-436537367);
        if (((i | (c0814p2.f(aVar) ? 4 : 2) | (c0814p2.h(function0) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128)) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(1767614893, new com.quizlet.explanations.questiondetail.ui.composables.m(19, function0), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-128383944, new com.quizlet.features.settings.composables.changetheme.c(aVar, function1, 1), c0814p2), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 17, aVar, function0, function1);
        }
    }

    public static void c(String str, String str2, Object obj) {
        if (Log.isLoggable("TRuntime.".concat(str), 3)) {
            String.format(str2, obj);
        }
    }

    public static void d(String str, String str2, Exception exc) {
        String strConcat = "TRuntime.".concat(str);
        if (Log.isLoggable(strConcat, 6)) {
            Log.e(strConcat, str2, exc);
        }
    }
}
