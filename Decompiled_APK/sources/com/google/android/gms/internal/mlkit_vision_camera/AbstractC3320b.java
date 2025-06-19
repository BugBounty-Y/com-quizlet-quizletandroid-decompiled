package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3320b {
    public static final void a(androidx.glance.p pVar, int i, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        int i4;
        int i5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1883910253);
        int i6 = (c0814p.f(pVar) ? 4 : 2) | i2;
        int i7 = i3 & 2;
        if (i7 != 0) {
            i4 = i6 | 48;
        } else {
            i4 = i6 | (c0814p.d(i) ? 32 : 16);
        }
        if ((i3 & 4) != 0) {
            i5 = i4 | 384;
        } else {
            i5 = i4 | (c0814p.d(0) ? 256 : 128);
        }
        if ((i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i7 != 0) {
                i = 0;
            }
            androidx.glance.layout.f fVar = androidx.glance.layout.f.a;
            c0814p.Y(578571862);
            c0814p.Y(-548224868);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(fVar);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.layout.e.d);
            C0776c.E(c0814p, new androidx.glance.layout.a(0), androidx.glance.layout.e.e);
            C0776c.E(c0814p, new androidx.glance.layout.b(i), androidx.glance.layout.e.f);
            dVar.invoke(androidx.glance.layout.g.a, c0814p, 54);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        int i8 = i;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.ui.layout.b0(pVar, i8, dVar, i2, i3);
        }
    }

    public static final void b(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        Function0 function04;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(156127075);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
            function04 = function02;
        } else {
            function03 = function0;
            function04 = function02;
            W5.a(R.string.upload_notes_go_back_dialog_confirm_button, R.string.upload_notes_go_back_dialog_description, null, function03, function04, null, Integer.valueOf(R.string.upload_notes_go_back_dialog_header), Integer.valueOf(R.string.notes_cancel_button), c0814p, (i2 << 9) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function03, function04, i, 0);
        }
    }

    public static final double c(long j) {
        return ((j >>> 11) * 2048) + (j & 2047);
    }

    public static final String d(int i, long j) {
        if (j >= 0) {
            String string = Long.toString(j, CharsKt.checkRadix(i));
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            return string;
        }
        long j2 = i;
        long j3 = ((j >>> 1) / j2) << 1;
        long j4 = j - (j3 * j2);
        if (j4 >= j2) {
            j4 -= j2;
            j3++;
        }
        StringBuilder sb = new StringBuilder();
        String string2 = Long.toString(j3, CharsKt.checkRadix(i));
        Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
        sb.append(string2);
        String string3 = Long.toString(j4, CharsKt.checkRadix(i));
        Intrinsics.checkNotNullExpressionValue(string3, "toString(...)");
        sb.append(string3);
        return sb.toString();
    }
}
