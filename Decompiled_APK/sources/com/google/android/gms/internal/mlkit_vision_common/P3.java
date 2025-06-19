package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class P3 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, com.quizlet.data.model.m2 source, Function0 onLeaveButtonClick, Function0 onCancelButtonClick) {
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(onLeaveButtonClick, "onLeaveButtonClick");
        Intrinsics.checkNotNullParameter(onCancelButtonClick, "onCancelButtonClick");
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1967570519);
        int i4 = (c0814p.h(onLeaveButtonClick) ? 4 : 2) | i | (c0814p.f(source) ? 256 : 128);
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Intrinsics.checkNotNullParameter(source, "<this>");
            int iOrdinal = source.ordinal();
            if (iOrdinal == 0) {
                i2 = R.string.uuf_generating_content_dialog_study_guide_title;
            } else if (iOrdinal == 1) {
                i2 = R.string.uuf_generating_content_dialog_flashcards_title;
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i2 = R.string.uuf_generating_content_dialog_practice_tests_title;
            }
            Intrinsics.checkNotNullParameter(source, "<this>");
            int iOrdinal2 = source.ordinal();
            if (iOrdinal2 == 0) {
                i3 = R.string.uuf_generating_content_dialog_study_guide_description;
            } else if (iOrdinal2 == 1) {
                i3 = R.string.uuf_generating_content_dialog_flashcards_description;
            } else {
                if (iOrdinal2 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                i3 = R.string.uuf_generating_content_dialog_practice_tests_description;
            }
            W5.a(R.string.uuf_generating_content_dialog_confirm_button, i3, null, onLeaveButtonClick, onCancelButtonClick, null, Integer.valueOf(i2), Integer.valueOf(R.string.uuf_generating_content_dialog_dismiss_button), c0814p, (i4 << 9) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(onLeaveButtonClick, onCancelButtonClick, source, i, 19);
        }
    }

    public static void b(int i, int i2) {
        String strB;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strB = Q3.b("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strB = Q3.b("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strB);
        }
    }

    public static void c(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? d(i, i3, "start index") : (i2 < 0 || i2 > i3) ? d(i2, i3, "end index") : Q3.b("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static String d(int i, int i2, String str) {
        if (i < 0) {
            return Q3.b("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return Q3.b("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }
}
