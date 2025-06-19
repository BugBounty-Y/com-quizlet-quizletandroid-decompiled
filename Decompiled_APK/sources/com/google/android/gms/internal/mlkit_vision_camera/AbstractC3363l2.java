package com.google.android.gms.internal.mlkit_vision_camera;

import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.util.Property;
import android.view.View;
import android.view.animation.BaseInterpolator;
import com.quizlet.quizletandroid.R;
import java.util.Arrays;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.l2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3363l2 {
    /* JADX WARN: Removed duplicated region for block: B:30:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:52:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r18, int r19, androidx.compose.runtime.InterfaceC0806l r20, androidx.compose.ui.q r21, java.lang.String r22, java.lang.String r23) {
        /*
            Method dump skipped, instructions count: 223
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2.a(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, java.lang.String):void");
    }

    public static final void b(okhttp3.internal.concurrent.a aVar, okhttp3.internal.concurrent.c cVar, String str) {
        Logger logger = okhttp3.internal.concurrent.d.i;
        StringBuilder sb = new StringBuilder();
        sb.append(cVar.b);
        sb.append(' ');
        String str2 = String.format("%-22s", Arrays.copyOf(new Object[]{str}, 1));
        Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
        sb.append(str2);
        sb.append(": ");
        sb.append(aVar.a);
        logger.fine(sb.toString());
    }

    public static ObjectAnimator c(View view, androidx.transition.I i, int i2, int i3, float f, float f2, float f3, float f4, BaseInterpolator baseInterpolator, androidx.transition.r rVar) {
        float f5;
        float translationX = view.getTranslationX();
        float translationY = view.getTranslationY();
        if (((int[]) i.b.getTag(R.id.transition_position)) != null) {
            f = (r5[0] - i2) + translationX;
            f5 = (r5[1] - i3) + translationY;
        } else {
            f5 = f2;
        }
        view.setTranslationX(f);
        view.setTranslationY(f5);
        if (f == f3 && f5 == f4) {
            return null;
        }
        ObjectAnimator objectAnimatorOfPropertyValuesHolder = ObjectAnimator.ofPropertyValuesHolder(view, PropertyValuesHolder.ofFloat((Property<?, Float>) View.TRANSLATION_X, f, f3), PropertyValuesHolder.ofFloat((Property<?, Float>) View.TRANSLATION_Y, f5, f4));
        androidx.transition.J j = new androidx.transition.J(view, i.b, translationX, translationY);
        rVar.b(j);
        objectAnimatorOfPropertyValuesHolder.addListener(j);
        objectAnimatorOfPropertyValuesHolder.setInterpolator(baseInterpolator);
        return objectAnimatorOfPropertyValuesHolder;
    }

    public static final String d(long j) {
        String strG;
        if (j <= -999500000) {
            strG = android.support.v4.media.session.a.g((j - 500000000) / 1000000000, " s ", new StringBuilder());
        } else if (j <= -999500) {
            strG = android.support.v4.media.session.a.g((j - 500000) / 1000000, " ms", new StringBuilder());
        } else if (j <= 0) {
            strG = android.support.v4.media.session.a.g((j - com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) / 1000, " µs", new StringBuilder());
        } else if (j < 999500) {
            strG = android.support.v4.media.session.a.g((j + com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) / 1000, " µs", new StringBuilder());
        } else if (j < 999500000) {
            strG = android.support.v4.media.session.a.g((j + 500000) / 1000000, " ms", new StringBuilder());
        } else {
            strG = android.support.v4.media.session.a.g((j + 500000000) / 1000000000, " s ", new StringBuilder());
        }
        return androidx.compose.animation.d0.s(new Object[]{strG}, 1, "%6s", "format(format, *args)");
    }
}
