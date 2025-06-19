package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public abstract class N2 {
    public static final void a(androidx.compose.ui.n nVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-949374024);
        int i2 = i | 6 | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | (c0814p.h(function03) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            M2.a(function0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).J(), Z4.a(2131231594, c0814p, 0), AbstractC3106b5.d(c0814p, R.string.creator_marketing_modal_title), function02, AbstractC3106b5.d(c0814p, R.string.creator_marketing_modal_button_text), function03, c0814p, ((i2 << 9) & 3670016) | ((i2 >> 3) & 14) | (57344 & (i2 << 6)) | 12582912);
        }
        androidx.compose.ui.n nVar2 = nVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) nVar2, (Object) function0, (Object) function02, (Object) function03, i, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:57:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.ui.n r23, final java.lang.String r24, long r25, androidx.compose.ui.graphics.painter.b r27, final kotlin.jvm.functions.Function0 r28, androidx.compose.runtime.internal.d r29, androidx.compose.runtime.InterfaceC0806l r30, final int r31, final int r32) {
        /*
            Method dump skipped, instructions count: 273
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.N2.b(androidx.compose.ui.n, java.lang.String, long, androidx.compose.ui.graphics.painter.b, kotlin.jvm.functions.Function0, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }
}
