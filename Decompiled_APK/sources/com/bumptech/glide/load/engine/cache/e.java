package com.bumptech.glide.load.engine.cache;

import android.app.ActivityManager;
import android.content.Context;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class e {
    public final Context a;
    public final ActivityManager b;
    public final com.google.android.gms.internal.instantapps.a c;
    public final float d;

    public e(Context context) {
        this.d = 1;
        this.a = context;
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        this.b = activityManager;
        this.c = new com.google.android.gms.internal.instantapps.a(context.getResources().getDisplayMetrics(), 20);
        if (activityManager.isLowRamDevice()) {
            this.d = DefinitionKt.NO_Float_VALUE;
        }
    }
}
