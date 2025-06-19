package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L6;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.koin.core.error.DefinitionOverrideException;
import org.koin.core.error.KoinAppAlreadyStartedException;
import org.wordpress.aztec.C5146b;

/* loaded from: classes2.dex */
public abstract class H2 {
    public static final void a(com.quizlet.features.questiontypes.data.d dVar, DiagramData diagramData, androidx.compose.ui.q qVar, float f, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        float f2;
        float f3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1660538878);
        int i3 = (c0814p.h(dVar) ? 4 : 2) | i | (c0814p.h(diagramData) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | 1024;
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.h(function02) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.h(function03) ? 1048576 : 524288;
        }
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
            f3 = f;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                i2 = i3 & (-7169);
                f2 = com.quizlet.themes.m.l0;
            } else {
                c0814p.Q();
                i2 = i3 & (-7169);
                f2 = f;
            }
            c0814p.q();
            if ((dVar != null ? dVar.a : null) != null) {
                c0814p.X(706842102);
                int i4 = i2 & 14;
                int i5 = i2 >> 6;
                L2.a(dVar, androidx.compose.ui.platform.N.G(qVar, "standardView"), function0, function02, function03, c0814p, (i5 & 57344) | i4 | (i5 & 896) | (i5 & 7168));
                c0814p.p(false);
            } else if (diagramData != null) {
                c0814p.X(707159542);
                L6.a(diagramData, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.e(qVar, 0, f2), "diagramView"), null, false, null, null, null, null, c0814p, (i2 >> 3) & 14, 252);
                c0814p.p(false);
            } else {
                c0814p.X(707354935);
                AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
                c0814p.p(false);
            }
            f3 = f2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.composables.Y(dVar, diagramData, qVar, f3, function0, function02, function03, i);
        }
    }

    public static boolean b(C5146b attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter("background-color", "styleAttributeName");
        return attributes.a("style") && c("background-color", attributes).find();
    }

    public static Matcher c(String str, C5146b c5146b) {
        String value = c5146b.getValue("style");
        if (value == null) {
            value = "";
        }
        String strReplace = new Regex("\\s").replace(value, "");
        Pattern patternCompile = Pattern.compile("(?:;|\\A)" + str + ":(.+?)(?:;|$)", 10);
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        Matcher matcher = patternCompile.matcher(strReplace);
        Intrinsics.checkNotNullExpressionValue(matcher, "matcher(...)");
        return matcher;
    }

    public static String d(String styleAttributeName, C5146b attributes) {
        String strGroup;
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(styleAttributeName, "styleAttributeName");
        Matcher matcherC = c(styleAttributeName, attributes);
        return (!matcherC.find() || (strGroup = matcherC.group(1)) == null) ? "" : strGroup;
    }

    public static void e(ExperimentConfiguration experimentConfiguration) throws DefinitionOverrideException, KoinAppAlreadyStartedException {
        assistantMode.experiments.a block = new assistantMode.experiments.a(experimentConfiguration, 0);
        Intrinsics.checkNotNullParameter(block, "block");
        List listB = kotlin.collections.A.b(block.invoke());
        com.quizlet.data.repository.login.a aVar = com.quizlet.shared.di.a.a;
        if (aVar != null) {
            aVar.k(listB, true);
            return;
        }
        com.quizlet.assembly.compose.menu.e appDeclaration = new com.quizlet.assembly.compose.menu.e(listB, 26);
        Intrinsics.checkNotNullParameter(appDeclaration, "appDeclaration");
        org.koin.core.a aVar2 = new org.koin.core.a();
        if (com.quizlet.shared.di.a.a != null) {
            Intrinsics.checkNotNullParameter("A Koin Application has already been started", "msg");
            throw new KoinAppAlreadyStartedException("A Koin Application has already been started");
        }
        com.quizlet.shared.di.a.a = aVar2.a;
        aVar2.b = true;
        appDeclaration.invoke(aVar2);
    }
}
