package com.pubmatic.sdk.common.utility;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import com.pubmatic.sdk.common.log.POBLog;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class j {

    @NotNull
    public static final j INSTANCE = new j();

    @NotNull
    public static final String TAG = "POBSharedPreferenceUtil";

    private j() {
    }

    private final SharedPreferences a(Context context) {
        if (Build.VERSION.SDK_INT < 29) {
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            Intrinsics.checkNotNullExpressionValue(defaultSharedPreferences, "{\n      PreferenceManager.getDefaultSharedPreferences(context)\n    }");
            return defaultSharedPreferences;
        }
        SharedPreferences sharedPreferences = context.getSharedPreferences(context.getPackageName() + "_preferences", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "{\n      androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)\n    }");
        return sharedPreferences;
    }

    public static final Integer getIntegerFromSharedPreference(@NotNull Context context, @NotNull String key) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(key, "key");
        SharedPreferences sharedPreferencesA = INSTANCE.a(context);
        if (sharedPreferencesA == null || !sharedPreferencesA.contains(key)) {
            return null;
        }
        try {
            return Integer.valueOf(sharedPreferencesA.getInt(key, 0));
        } catch (ClassCastException e) {
            POBLog.warn(TAG, e.getMessage(), new Object[0]);
            return null;
        }
    }

    public static final String getStringFromSharedPreference(@NotNull Context context, @NotNull String key, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(key, "key");
        SharedPreferences sharedPreferencesA = INSTANCE.a(context);
        if (sharedPreferencesA == null) {
            return null;
        }
        return sharedPreferencesA.getString(key, str);
    }
}
