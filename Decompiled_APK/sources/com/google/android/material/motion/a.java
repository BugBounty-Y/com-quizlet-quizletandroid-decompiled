package com.google.android.material.motion;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.Log;
import android.view.View;
import android.view.animation.PathInterpolator;
import androidx.activity.C0030b;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public abstract class a {
    public final TimeInterpolator a;
    public final View b;
    public final int c;
    public final int d;
    public final int e;
    public C0030b f;

    public a(View view) {
        this.b = view;
        Context context = view.getContext();
        this.a = AbstractC3430b4.e(context, R.attr.motionEasingStandardDecelerateInterpolator, new PathInterpolator(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f));
        this.c = AbstractC3430b4.d(context, R.attr.motionDurationMedium2, 300);
        this.d = AbstractC3430b4.d(context, R.attr.motionDurationShort3, 150);
        this.e = AbstractC3430b4.d(context, R.attr.motionDurationShort2, 100);
    }

    public final C0030b a() {
        if (this.f == null) {
            Log.w("MaterialBackHelper", "Must call startBackProgress() and updateBackProgress() before cancelBackProgress()");
        }
        C0030b c0030b = this.f;
        this.f = null;
        return c0030b;
    }
}
