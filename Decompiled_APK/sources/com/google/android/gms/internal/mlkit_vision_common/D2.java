package com.google.android.gms.internal.mlkit_vision_common;

import android.app.Activity;
import android.view.View;
import android.view.ViewTreeObserver;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D2 {
    public static final void a(com.quizlet.features.settings.composables.a aboutActions, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(aboutActions, "aboutActions");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-966738086);
        if ((((c0814p.f(aboutActions) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            M2.c(AbstractC3106b5.d(c0814p, R.string.about_section_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1261859114, new com.quizlet.assembly.compose.cards.c(aboutActions, 20), c0814p), c0814p, 0, 1022);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(aboutActions, qVar2, i, 4);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1121657690);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.help_center_title), null, null, com.quizlet.features.settings.composables.c.d, function02, c0814p, ((i2 << 12) & 57344) | 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 6, function02);
        }
    }

    public static final void c(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1131012345);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.open_source_licenses_title), null, null, com.quizlet.features.settings.composables.c.c, function02, c0814p, ((i2 << 12) & 57344) | 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 7, function02);
        }
    }

    public static final void d(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-208701038);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.privacy_policy_title), null, null, com.quizlet.features.settings.composables.c.a, function02, c0814p, ((i2 << 12) & 57344) | 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 5, function02);
        }
    }

    public static final void e(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(500604249);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.terms_of_service_title), null, null, com.quizlet.features.settings.composables.c.b, function02, c0814p, ((i2 << 12) & 57344) | 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 8, function02);
        }
    }

    public static void f(Activity activity) {
        View viewC;
        Intrinsics.checkNotNullParameter(activity, "activity");
        int iHashCode = activity.hashCode();
        HashMap map = com.facebook.appevents.suggestedevents.e.d;
        HashMap map2 = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.suggestedevents.e.class)) {
            try {
                map2 = com.facebook.appevents.suggestedevents.e.d;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.suggestedevents.e.class, th);
            }
        }
        Integer numValueOf = Integer.valueOf(iHashCode);
        Object eVar = map2.get(numValueOf);
        if (eVar == null) {
            eVar = new com.facebook.appevents.suggestedevents.e(activity);
            map2.put(numValueOf, eVar);
        }
        com.facebook.appevents.suggestedevents.e eVar2 = (com.facebook.appevents.suggestedevents.e) eVar;
        if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.suggestedevents.e.class)) {
            return;
        }
        try {
            if (com.facebook.internal.instrument.crashshield.a.b(eVar2)) {
                return;
            }
            try {
                if (!eVar2.c.getAndSet(true) && (viewC = com.facebook.appevents.internal.d.c((Activity) eVar2.a.get())) != null) {
                    ViewTreeObserver viewTreeObserver = viewC.getViewTreeObserver();
                    if (viewTreeObserver.isAlive()) {
                        viewTreeObserver.addOnGlobalLayoutListener(eVar2);
                        eVar2.a();
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(eVar2, th2);
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.suggestedevents.e.class, th3);
        }
    }

    public static void g(Activity activity) {
        View viewC;
        Intrinsics.checkNotNullParameter(activity, "activity");
        int iHashCode = activity.hashCode();
        HashMap map = com.facebook.appevents.suggestedevents.e.d;
        HashMap map2 = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.suggestedevents.e.class)) {
            try {
                map2 = com.facebook.appevents.suggestedevents.e.d;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.suggestedevents.e.class, th);
            }
        }
        com.facebook.appevents.suggestedevents.e eVar = (com.facebook.appevents.suggestedevents.e) map2.remove(Integer.valueOf(iHashCode));
        if (eVar == null || com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.suggestedevents.e.class)) {
            return;
        }
        try {
            if (!com.facebook.internal.instrument.crashshield.a.b(eVar)) {
                try {
                    if (eVar.c.getAndSet(false) && (viewC = com.facebook.appevents.internal.d.c((Activity) eVar.a.get())) != null) {
                        ViewTreeObserver viewTreeObserver = viewC.getViewTreeObserver();
                        if (viewTreeObserver.isAlive()) {
                            viewTreeObserver.removeOnGlobalLayoutListener(eVar);
                        }
                    }
                } catch (Throwable th2) {
                    com.facebook.internal.instrument.crashshield.a.a(eVar, th2);
                }
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.suggestedevents.e.class, th3);
        }
    }
}
