package com.quizlet.quizletandroid.databinding;

import android.widget.ImageView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.preview.SetPreviewOnboarding;

/* loaded from: classes3.dex */
public abstract class i0 implements androidx.viewbinding.a {
    public static void a(SetPreviewOnboarding setPreviewOnboarding) {
        int i = R.id.hand_pointer;
        if (((ImageView) AbstractC3375o2.c(R.id.hand_pointer, setPreviewOnboarding)) != null) {
            i = R.id.leftArrow;
            if (((ImageView) AbstractC3375o2.c(R.id.leftArrow, setPreviewOnboarding)) != null) {
                i = R.id.rightArrow;
                if (((ImageView) AbstractC3375o2.c(R.id.rightArrow, setPreviewOnboarding)) != null) {
                    i = R.id.tooltipOnboardingText;
                    if (((QTextView) AbstractC3375o2.c(R.id.tooltipOnboardingText, setPreviewOnboarding)) != null) {
                        return;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(setPreviewOnboarding.getResources().getResourceName(i)));
    }
}
