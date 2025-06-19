package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.gtm.zzen;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.c3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3435c3 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(803210812);
        if (((i | 6 | (c0814p.h(function0) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            AbstractC3579a6.e(AbstractC3106b5.d(c0814p, R.string.change_email_confirmation_dialog_message), nVar2, AbstractC3106b5.d(c0814p, R.string.change_email_confirmation_dialog_title), androidx.compose.runtime.internal.e.e(1506978197, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(11, function0), c0814p), null, 0, c0814p, 3120, 48);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.A(nVar, function0, i, 4);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-834842698);
        if ((((c0814p.h(function0) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            S5.a(null, 0L, DefinitionKt.NO_Float_VALUE, 0L, null, androidx.compose.runtime.internal.e.e(-1570104546, new com.quizlet.explanations.questiondetail.ui.composables.m(20, function0), c0814p), c0814p, 196608, 31);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 9, function0);
        }
    }

    public static String c(int i, String str) {
        if (i <= 0) {
            zzen.zzb("index out of range for prefix", str);
            return "";
        }
        return str + i;
    }
}
