package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4389h;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.m7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3207m7 {
    public static final void a(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function03;
        Function0 function04;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-159826463);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function02) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
            function04 = function02;
        } else {
            function03 = function0;
            function04 = function02;
            com.google.android.gms.internal.mlkit_vision_document_scanner.W5.a(R.string.magic_notes_detail_delete, R.string.magic_notes_detail_delete_desc, null, function03, function04, null, Integer.valueOf(R.string.magic_notes_detail_delete_are_sure), Integer.valueOf(R.string.notes_cancel_button), c0814p, (i2 << 9) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4389h(function03, function04, i, 0);
        }
    }

    public static final androidx.glance.p b(androidx.glance.p pVar, androidx.glance.appwidget.action.e eVar) {
        return pVar.d(new androidx.glance.action.b(eVar));
    }
}
