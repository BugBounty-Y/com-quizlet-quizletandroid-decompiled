package androidx.lifecycle;

import android.app.Activity;
import androidx.lifecycle.C1242c0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1240b0 {
    public static final void a(Activity activity, C1242c0.a callback) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(callback, "callback");
        activity.registerActivityLifecycleCallbacks(callback);
    }
}
