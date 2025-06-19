package com.quizlet.eventlogger;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class NotificationDeviceStatus {

    @NotNull
    private static final String PREFS = "PREFS_NOTIFICATION_DEVICE_STATUS";

    @NotNull
    private static final String PRES_NOTIFICATION_CHANNELS_STATUS = "PREF_NOTIFICATION_CHANNELS_STATUS";

    @NotNull
    private static final String PRES_NOTIFICATION_DEVICE_STATUS = "PREF_NOTIFICATION_DEVICE_STATUS";
    private final SharedPreferences sharedPreferences;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        new Companion(null);
    }

    public NotificationDeviceStatus(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.sharedPreferences = context.getSharedPreferences(PREFS, 0);
    }

    public final String getNotificationChannelsStatus() {
        if (this.sharedPreferences.contains(PRES_NOTIFICATION_CHANNELS_STATUS)) {
            return this.sharedPreferences.getString(PRES_NOTIFICATION_CHANNELS_STATUS, "");
        }
        return null;
    }

    public final Boolean getNotificationDeviceStatus() {
        if (this.sharedPreferences.contains(PRES_NOTIFICATION_DEVICE_STATUS)) {
            return Boolean.valueOf(this.sharedPreferences.getBoolean(PRES_NOTIFICATION_DEVICE_STATUS, false));
        }
        return null;
    }

    public final void setNotificationChannelsStatus(String str) {
        if (str != null) {
            this.sharedPreferences.edit().putString(PRES_NOTIFICATION_CHANNELS_STATUS, str).apply();
        }
    }

    public final void setNotificationDeviceStatus(boolean z) {
        assistantMode.refactored.a.p(this.sharedPreferences, PRES_NOTIFICATION_DEVICE_STATUS, z);
    }
}
