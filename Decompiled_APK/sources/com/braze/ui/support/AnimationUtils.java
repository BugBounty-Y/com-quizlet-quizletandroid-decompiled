package com.braze.ui.support;

import android.view.animation.AccelerateInterpolator;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.TranslateAnimation;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class AnimationUtils {

    @NotNull
    private static final Interpolator accelerateInterpolator = new AccelerateInterpolator();

    @NotNull
    private static final Interpolator decelerateInterpolator = new DecelerateInterpolator();

    @NotNull
    public static final Animation createVerticalAnimation(float f, float f2, long j, boolean z) {
        return setAnimationParams(new TranslateAnimation(2, DefinitionKt.NO_Float_VALUE, 2, DefinitionKt.NO_Float_VALUE, 1, f, 1, f2), j, z);
    }

    @NotNull
    public static final Animation setAnimationParams(@NotNull Animation animation, long j, boolean z) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        animation.setDuration(j);
        if (z) {
            animation.setInterpolator(accelerateInterpolator);
            return animation;
        }
        animation.setInterpolator(decelerateInterpolator);
        return animation;
    }
}
