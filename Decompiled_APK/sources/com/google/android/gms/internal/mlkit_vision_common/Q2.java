package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q2 {
    public static final void a(androidx.navigation.H navHostController, com.quizlet.features.settings.viewmodels.m mVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.settings.viewmodels.m mVar2;
        androidx.navigation.H h;
        Intrinsics.checkNotNullParameter(navHostController, "navHostController");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-665278069);
        int i2 = (c0814p.h(navHostController) ? 4 : 2) | i | (c0814p.f(mVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
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
            c0814p.X(-336727266);
            boolean z = (((i2 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.h(mVar)) || (i2 & 48) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                com.quizlet.features.settings.composables.x xVar = new com.quizlet.features.settings.composables.x(1, mVar, com.quizlet.features.settings.viewmodels.m.class, "onThemeSelected", "onThemeSelected(Lcom/quizlet/themes/nighttheme/NightThemeMode;)V", 0, 3);
                mVar2 = mVar;
                c0814p.i0(xVar);
                objI = xVar;
            } else {
                mVar2 = mVar;
            }
            c0814p.p(false);
            Function1 function1 = (Function1) ((kotlin.reflect.f) objI);
            c0814p.X(-336725663);
            boolean zH = c0814p.h(navHostController);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, navHostController, androidx.navigation.H.class, "navigateUp", "navigateUp()Z", 8, 6);
                h = navHostController;
                c0814p.i0(cVar);
                objI2 = cVar;
            } else {
                h = navHostController;
            }
            c0814p.p(false);
            b(aVar, function1, (Function0) objI2, c0814p, 0, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changetheme.b(h, mVar2, i, 0);
        }
    }

    public static final void b(com.quizlet.themes.nighttheme.a aVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Object obj;
        int i4;
        Object obj2;
        int i5;
        Object obj3;
        Object obj4;
        Object obj5;
        Object obj6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1717199272);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.f(aVar) ? 4 : 2);
        } else {
            i3 = i;
        }
        int i6 = i2 & 2;
        if (i6 != 0) {
            i4 = i3 | 48;
            obj = function1;
        } else {
            obj = function1;
            i4 = i3 | (c0814p.h(obj) ? 32 : 16);
        }
        int i7 = i2 & 4;
        if (i7 != 0) {
            i5 = i4 | 384;
            obj2 = function0;
        } else {
            obj2 = function0;
            i5 = i4 | (c0814p.h(obj2) ? 256 : 128);
        }
        if ((i5 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            obj5 = obj2;
            obj6 = obj;
        } else {
            Object obj7 = C0804k.a;
            if (i6 != 0) {
                c0814p.X(2007952175);
                Object objI = c0814p.I();
                if (objI == obj7) {
                    objI = new com.quizlet.features.practicetest.navigation.a(23);
                    c0814p.i0(objI);
                }
                obj3 = (Function1) objI;
                c0814p.p(false);
            } else {
                obj3 = obj;
            }
            if (i7 != 0) {
                c0814p.X(2007953263);
                Object objI2 = c0814p.I();
                if (objI2 == obj7) {
                    objI2 = new C4392k(24);
                    c0814p.i0(objI2);
                }
                obj4 = (Function0) objI2;
                c0814p.p(false);
            } else {
                obj4 = obj2;
            }
            S5.a(null, 0L, DefinitionKt.NO_Float_VALUE, 0L, null, androidx.compose.runtime.internal.e.e(-494800112, new com.quizlet.assembly.compose.menu.l(aVar, obj3, obj4, 22), c0814p), c0814p, 196608, 31);
            obj5 = obj4;
            obj6 = obj3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i, i2, 7, aVar, obj6, obj5);
        }
    }

    public static String c(String str, String str2) {
        int length = str.length() - str2.length();
        if (length < 0 || length > 1) {
            throw new IllegalArgumentException("Invalid input received");
        }
        StringBuilder sb = new StringBuilder(str2.length() + str.length());
        for (int i = 0; i < str.length(); i++) {
            sb.append(str.charAt(i));
            if (str2.length() > i) {
                sb.append(str2.charAt(i));
            }
        }
        return sb.toString();
    }
}
