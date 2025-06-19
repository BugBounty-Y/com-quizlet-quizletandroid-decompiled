package com.google.android.gms.internal.mlkit_vision_common;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.view.View;
import android.view.ViewAnimationUtils;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class W3 {
    public static final void a(com.quizlet.data.model.m2 source, boolean z, com.quizlet.assembly.compose.modals.x modalState, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-463075136);
        int i2 = i | (c0814p.f(source) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.h(modalState) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(180285333);
            com.quizlet.data.model.m2 m2Var = com.quizlet.data.model.m2.a;
            if (source == m2Var) {
                throw new kotlin.n(null, 1, null);
            }
            com.quizlet.data.model.m2 m2Var2 = com.quizlet.data.model.m2.b;
            if (source == m2Var2) {
                throw new kotlin.n(null, 1, null);
            }
            com.quizlet.data.model.m2 m2Var3 = com.quizlet.data.model.m2.c;
            if (source != m2Var3) {
                throw new NoWhenBranchMatchedException();
            }
            String strD = AbstractC3106b5.d(c0814p, R.string.uuf_privacy_settings_public_label_description_practice_tests);
            c0814p.p(false);
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(2091639031);
            if (source == m2Var) {
                throw new kotlin.n(null, 1, null);
            }
            if (source == m2Var2) {
                throw new kotlin.n(null, 1, null);
            }
            if (source != m2Var3) {
                throw new NoWhenBranchMatchedException();
            }
            String strD2 = AbstractC3106b5.d(c0814p, R.string.uuf_privacy_settings_private_label_description_practice_tests);
            c0814p.p(false);
            int i3 = i2 >> 3;
            A5.b(z, modalState, strD, strD2, function1, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 14) | 64 | ((i2 << 3) & 57344));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(source, z, modalState, function1, i, 5);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static AnimatorSet b(com.google.android.material.circularreveal.g gVar, float f, float f2, float f3) {
        ObjectAnimator objectAnimatorOfObject = ObjectAnimator.ofObject(gVar, com.google.android.material.circularreveal.d.a, com.google.android.material.circularreveal.c.b, new com.google.android.material.circularreveal.f(f, f2, f3));
        com.google.android.material.circularreveal.f revealInfo = gVar.getRevealInfo();
        if (revealInfo == null) {
            throw new IllegalStateException("Caller must set a non-null RevealInfo before calling this.");
        }
        Animator animatorCreateCircularReveal = ViewAnimationUtils.createCircularReveal((View) gVar, (int) f, (int) f2, revealInfo.c, f3);
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(objectAnimatorOfObject, animatorCreateCircularReveal);
        return animatorSet;
    }
}
