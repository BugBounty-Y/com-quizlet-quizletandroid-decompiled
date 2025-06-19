package com.google.android.gms.internal.mlkit_vision_common;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V3 {
    public static final void a(Function0 onCtaButtonClick, Function0 onDismiss, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function0;
        Function0 function02;
        Intrinsics.checkNotNullParameter(onCtaButtonClick, "onCtaButtonClick");
        Intrinsics.checkNotNullParameter(onDismiss, "onDismiss");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2090079660);
        int i2 = (c0814p.h(onCtaButtonClick) ? 4 : 2) | i | (c0814p.h(onDismiss) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function0 = onCtaButtonClick;
            function02 = onDismiss;
        } else {
            function0 = onCtaButtonClick;
            function02 = onDismiss;
            W5.a(R.string.uuf_flashcard_set_private_confirm_button, R.string.uuf_flashcard_set_private_description, null, function0, function02, null, Integer.valueOf(R.string.uuf_flashcard_set_private_header), Integer.valueOf(R.string.uuf_flashcard_set_private_dismiss_button), c0814p, (i2 << 9) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function0, function02, i, 5);
        }
    }

    public static void b(AnimatorSet animatorSet, ArrayList arrayList) {
        int size = arrayList.size();
        long jMax = 0;
        for (int i = 0; i < size; i++) {
            Animator animator = (Animator) arrayList.get(i);
            jMax = Math.max(jMax, animator.getDuration() + animator.getStartDelay());
        }
        ValueAnimator valueAnimatorOfInt = ValueAnimator.ofInt(0, 0);
        valueAnimatorOfInt.setDuration(jMax);
        arrayList.add(0, valueAnimatorOfInt);
        animatorSet.playTogether(arrayList);
    }
}
