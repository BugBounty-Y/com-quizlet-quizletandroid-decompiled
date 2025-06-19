package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.error.DefinitionOverrideException;
import org.koin.core.error.KoinAppAlreadyStartedException;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.u2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3398u2 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onDismissClick, Function0 onConfirmClick) {
        Intrinsics.checkNotNullParameter(onDismissClick, "onDismissClick");
        Intrinsics.checkNotNullParameter(onConfirmClick, "onConfirmClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1346073182);
        int i2 = (c0814p.h(onDismissClick) ? 4 : 2) | i | (c0814p.h(onConfirmClick) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            W5.a(R.string.practice_test_taking_dialog_submit_button, R.string.practice_test_taking_dialog_unanswered_description, androidx.compose.ui.platform.N.G(qVar, "PracticeTestTakingUnansweredDialog"), onConfirmClick, onDismissClick, null, Integer.valueOf(R.string.practice_test_taking_dialog_unanswered_title), Integer.valueOf(R.string.practice_test_taking_dialog_go_back_button), c0814p, ((i2 << 6) & 7168) | ((i2 << 12) & 57344), 32);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.k(onDismissClick, onConfirmClick, qVar2, i, 3);
        }
    }

    public static void b(org.koin.core.module.a module) throws DefinitionOverrideException, KoinAppAlreadyStartedException {
        Intrinsics.checkNotNullParameter(module, "module");
        List listB = kotlin.collections.A.b(module);
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
