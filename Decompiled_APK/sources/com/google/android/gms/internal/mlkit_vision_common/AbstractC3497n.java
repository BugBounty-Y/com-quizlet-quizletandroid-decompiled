package com.google.android.gms.internal.mlkit_vision_common;

import android.webkit.MimeTypeMap;
import androidx.compose.foundation.layout.AbstractC0377b0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import java.util.Locale;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3497n {
    public static final void a(com.quizlet.features.setpage.header.viewmodel.b bVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(206510253);
        int i2 = (c0814p.h(bVar) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            AbstractC3515q.c(bVar.a, bVar.b, qVar2, bVar.c, bVar.d, bVar.e, c0814p, (i2 << 3) & 896);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(bVar, qVar2, i, 3);
        }
    }

    public static final void b(kotlinx.collections.immutable.b buttonsList, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        float f;
        float f2;
        int i4 = 4;
        Intrinsics.checkNotNullParameter(buttonsList, "buttonsList");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1628017250);
        if ((((c0814p.h(buttonsList) ? 4 : 2) | i2 | 176) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
            i3 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                qVar2 = androidx.compose.ui.n.b;
                i3 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                qVar2 = qVar;
                i3 = i;
            }
            c0814p.q();
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            boolean z = i3 == 0;
            boolean z2 = !z;
            int i5 = !z ? 2 : 1;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            if (z) {
                mVar.u();
                f = com.quizlet.ui.resources.designsystem.generated.j.g;
            } else {
                mVar.s();
                f = com.quizlet.ui.resources.designsystem.generated.j.h;
            }
            if (z) {
                mVar.u();
                f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            } else {
                f2 = com.quizlet.themes.m.R;
            }
            AbstractC0377b0.b(androidx.compose.ui.platform.N.G(AbstractC0382e.u(qVar2.g(androidx.compose.foundation.layout.K0.c), f), "FlowRow"), AbstractC0398m.g(com.quizlet.themes.m.R), AbstractC0398m.g(f2), i5, 0, null, androidx.compose.runtime.internal.e.e(-372165219, new com.quizlet.features.flashcards.views.c(z2, i4, buttonsList), c0814p), c0814p, 1572864, 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(buttonsList, qVar2, i3, i2);
        }
    }

    public static String c(String str) {
        if (StringsKt.O(str)) {
            return null;
        }
        String strE0 = StringsKt.e0(StringsKt.e0(str, '#'), '?');
        String strC0 = StringsKt.c0(StringsKt.c0(strE0, strE0, '/'), "", '.');
        if (StringsKt.O(strC0)) {
            return null;
        }
        String lowerCase = strC0.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        String str2 = (String) coil3.util.i.a.get(lowerCase);
        return str2 == null ? MimeTypeMap.getSingleton().getMimeTypeFromExtension(lowerCase) : str2;
    }
}
