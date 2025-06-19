package com.quizlet.quizletandroid.ui.base;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import androidx.appcompat.app.AbstractActivityC0055k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a(AbstractActivityC0055k activity) throws PackageManager.NameNotFoundException {
        Intrinsics.checkNotNullParameter(activity, "activity");
        ActivityInfo activityInfo = activity.getPackageManager().getActivityInfo(activity.getComponentName(), 128);
        Intrinsics.checkNotNullExpressionValue(activityInfo, "getActivityInfo(...)");
        Bundle bundle = activityInfo.metaData;
        if (bundle == null) {
            throw new IllegalStateException("Activity not mapped for logging: ".concat(activity.getClass().getSimpleName()));
        }
        String string = bundle.getString("com.quizlet.quizletandroid.loggingTag");
        if (string == null || string.length() == 0) {
            throw new IllegalStateException("Activity not mapped for logging: ".concat(activity.getClass().getSimpleName()));
        }
        return string;
    }
}
