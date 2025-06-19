package com.quizlet.quizletandroid.ui.common.ads.nativeads;

import android.app.Activity;
import android.app.Application;
import android.content.SharedPreferences;
import android.os.Bundle;
import com.quizlet.ads.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Application.ActivityLifecycleCallbacks {
    public final d a;
    public int b;
    public boolean c;

    public a(d adUnitSharedPreferencesManager) {
        Intrinsics.checkNotNullParameter(adUnitSharedPreferencesManager, "adUnitSharedPreferencesManager");
        this.a = adUnitSharedPreferencesManager;
        this.c = true;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        int i = this.b + 1;
        this.b = i;
        if (i == 1 && this.c) {
            this.c = false;
            d dVar = this.a;
            long j = dVar.a;
            String strValueOf = String.valueOf(j);
            SharedPreferences sharedPreferences = dVar.b;
            sharedPreferences.edit().putInt(String.valueOf(j), sharedPreferences.getInt(strValueOf, 0) + 1).apply();
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.b--;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(outState, "outState");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }
}
