package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.r6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3714r6 {
    public static final void a(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n uiState, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1227083026);
        if (((i | (c0814p2.h(uiState) ? 4 : 2) | 48 | (c0814p2.h(function1) ? 256 : 128)) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(nVar, "learn_round_summary_focused_learn"), null, null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(688005729, new com.quizlet.features.questiontypes.mcq.ui.c(10, uiState, function1), c0814p2), c0814p, 805306368, 446);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 1, uiState, qVar2, function1);
        }
    }

    public static final com.quizlet.billing.model.b b(DBUser dBUser) {
        return dBUser == null ? new com.quizlet.billing.model.b(0, 0, 31, 0L, (String) null) : new com.quizlet.billing.model.b(dBUser.getId(), dBUser.getObfuscatedUserId(), dBUser.getSelfIdentifiedUserType(), dBUser.getUserUpgradeType(), dBUser.getIsEligibleForFreeTrial());
    }
}
