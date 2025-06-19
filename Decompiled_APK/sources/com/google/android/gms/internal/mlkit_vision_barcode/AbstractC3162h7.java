package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.C0972v0;
import androidx.compose.ui.platform.ComposeView;
import androidx.fragment.app.Fragment;
import androidx.navigation.compose.C1280m;
import com.quizlet.data.model.EssayItem;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.h7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3162h7 {
    public static final void a(EssayItem essayItem, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(essayItem, "essayItem");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(754184270);
        if ((((c0814p2.h(essayItem) ? 4 : 2) | i | (c0814p2.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1885656200, new com.quizlet.assembly.compose.cards.c(essayItem, 12), c0814p2), c0814p, 0, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(essayItem, qVar, i, 18);
        }
    }

    public static final ComposeView b(Fragment fragment, androidx.compose.runtime.internal.d dVar) {
        ComposeView composeView = new ComposeView(fragment.requireContext(), null, 6);
        composeView.setViewCompositionStrategy(C0972v0.b);
        composeView.setContent(dVar);
        return composeView;
    }

    public static void c(io.ktor.util.l lVar, Function2 body) {
        Intrinsics.checkNotNullParameter(body, "body");
        for (Map.Entry entry : lVar.a()) {
            body.invoke((String) entry.getKey(), (List) entry.getValue());
        }
    }
}
