package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.g3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3459g3 {
    public static final void a(com.quizlet.features.settings.data.models.b bVar, com.quizlet.assembly.compose.modals.x xVar, Function1 function1, Function0 function0, boolean z, com.quizlet.qutils.string.g gVar, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(827298260);
        int i2 = i | (c0814p.f(bVar) ? 4 : 2) | (c0814p.h(xVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.g(z) ? 16384 : 8192) | (c0814p.h(gVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p.j(AbstractC0955m0.n);
            c0814p.X(515207670);
            boolean zF = c0814p.f(q0);
            Object objI = c0814p.I();
            if (zF || objI == v) {
                function02 = function0;
                objI = new com.quizlet.assembly.compose.modals.w(q0, function02, 8);
                c0814p.i0(objI);
            } else {
                function02 = function0;
            }
            c0814p.p(false);
            V5.a(null, xVar, false, null, (Function0) objI, null, androidx.compose.runtime.internal.e.e(-349965952, new com.quizlet.features.infra.folder.create.composables.a(bVar, function1, xVar, function02, z, gVar), c0814p), c0814p, 1572928 | (i2 & ContentType.LONG_FORM_ON_DEMAND), 45);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.emailconfirmation.ui.composables.e(bVar, xVar, function1, function0, z, gVar, i);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, com.quizlet.qutils.string.g gVar, String str, Function0 function0, Function1 function1, boolean z) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1602458664);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.h(function1) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.h(gVar) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strD = AbstractC3106b5.d(c0814p2, R.string.settings_reauth_password_message);
            String strD2 = AbstractC3106b5.d(c0814p2, R.string.settings_reauth_password_input_hint);
            c0814p2.X(-212530901);
            String strA = gVar == null ? null : gVar.a((Context) c0814p2.j(AndroidCompositionLocals_androidKt.b));
            c0814p2.p(false);
            c0814p = c0814p2;
            X5.a(strD, null, str, strD2, strA, 7, z, null, function1, null, function0, c0814p, ((i2 << 6) & 896) | 1572864 | ((i2 << 12) & 29360128) | ((i2 << 24) & 1879048192), (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(str, function1, function0, z, gVar, i);
        }
    }
}
