package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.d3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3441d3 {
    public static final void a(com.quizlet.features.settings.data.models.b bVar, com.quizlet.assembly.compose.modals.x xVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1240575572);
        int i2 = i | (c0814p.f(bVar) ? 4 : 2) | (c0814p.h(xVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            U5.b(xVar, null, false, null, null, function02, androidx.compose.runtime.internal.e.e(-189090439, new com.quizlet.features.settings.composables.dialogs.d(bVar, function0, xVar, function02, 0), c0814p), c0814p, ((i2 >> 3) & 14) | 1769480, 30);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.b(bVar, xVar, function0, function02, i, 0);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, String str, Function0 function0, Function0 function02) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(523173901);
        int i2 = i | 6 | (c0814p.f(str) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            AbstractC3579a6.e(AbstractC3106b5.d(c0814p, R.string.settings_reauth_facebook_message), nVar3, str, androidx.compose.runtime.internal.e.e(2139072660, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(12, function0), c0814p), androidx.compose.runtime.internal.e.e(2004489971, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(13, function02), c0814p), 0, c0814p, 27696 | ((i2 << 3) & 896), 32);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.c(nVar2, str, function0, function02, i, 0);
        }
    }

    public static com.google.android.gms.internal.p000authapi.b c(Context context) {
        com.google.android.gms.common.internal.u.h(context);
        return new com.google.android.gms.internal.p000authapi.b(context, new com.google.android.gms.auth.api.identity.h());
    }
}
