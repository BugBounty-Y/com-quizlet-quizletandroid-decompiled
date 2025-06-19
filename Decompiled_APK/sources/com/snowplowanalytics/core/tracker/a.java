package com.snowplowanalytics.core.tracker;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.F6;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Application.ActivityLifecycleCallbacks {
    public static final com.quizlet.quizletandroid.ui.common.images.capture.b b = new com.quizlet.quizletandroid.ui.common.images.capture.b(5);
    public static a c;
    public Integer a;

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Integer num = this.a;
        if (num == null || num.intValue() != activity.hashCode()) {
            this.a = Integer.valueOf(activity.hashCode());
            Intrinsics.checkNotNullExpressionValue("a", "TAG");
            e.a("a", "Auto screenview occurred - activity has resumed", new Object[0]);
            try {
                com.snowplowanalytics.snowplow.event.e eVarA = F6.a(activity);
                HashMap map = new HashMap();
                map.put("event", eVarA);
                com.snowplowanalytics.core.utils.c.b(map, "SnowplowScreenView");
            } catch (Exception e) {
                Intrinsics.checkNotNullExpressionValue("a", "TAG");
                e.b("a", "Method onActivityResumed raised an exception: %s", e);
            }
        }
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
