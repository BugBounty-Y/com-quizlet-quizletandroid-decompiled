package com.google.android.material.appbar;

import android.R;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public abstract class o {
    public static final int[] a = {R.attr.stateListAnimator};

    public static void a(AppBarLayout appBarLayout, float f) {
        int integer = appBarLayout.getResources().getInteger(com.quizlet.quizletandroid.R.integer.app_bar_elevation_anim_duration);
        StateListAnimator stateListAnimator = new StateListAnimator();
        long j = integer;
        stateListAnimator.addState(new int[]{R.attr.state_enabled, com.quizlet.quizletandroid.R.attr.state_liftable, -2130970283}, ObjectAnimator.ofFloat(appBarLayout, "elevation", DefinitionKt.NO_Float_VALUE).setDuration(j));
        stateListAnimator.addState(new int[]{R.attr.state_enabled}, ObjectAnimator.ofFloat(appBarLayout, "elevation", f).setDuration(j));
        stateListAnimator.addState(new int[0], ObjectAnimator.ofFloat(appBarLayout, "elevation", DefinitionKt.NO_Float_VALUE).setDuration(0L));
        appBarLayout.setStateListAnimator(stateListAnimator);
    }
}
