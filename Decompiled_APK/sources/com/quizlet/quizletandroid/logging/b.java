package com.quizlet.quizletandroid.logging;

import android.content.Context;
import android.content.pm.PackageManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quizlet.data.repository.qclass.c;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.NotificationDeviceStatus;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.internal.d;

/* loaded from: classes3.dex */
public final class b {
    public final d a;
    public final Context b;
    public final EventLogger c;
    public final com.quizlet.data.repository.user.a d;
    public final com.quizlet.data.interactor.school.b e;
    public final NotificationDeviceStatus f;
    public final c g;
    public final ObjectMapper h;

    public b(d defaultScope, Context appContext, EventLogger mEventLogger, com.quizlet.data.repository.user.a mGaLogger, com.quizlet.data.interactor.school.b mAccessibilityServiceLogger, NotificationDeviceStatus mNotificationDeviceStatus, c notificationChannelsManager, ObjectMapper mObjectMapper) {
        Intrinsics.checkNotNullParameter(defaultScope, "defaultScope");
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(mEventLogger, "mEventLogger");
        Intrinsics.checkNotNullParameter(mGaLogger, "mGaLogger");
        Intrinsics.checkNotNullParameter(mAccessibilityServiceLogger, "mAccessibilityServiceLogger");
        Intrinsics.checkNotNullParameter(mNotificationDeviceStatus, "mNotificationDeviceStatus");
        Intrinsics.checkNotNullParameter(notificationChannelsManager, "notificationChannelsManager");
        Intrinsics.checkNotNullParameter(mObjectMapper, "mObjectMapper");
        this.a = defaultScope;
        this.b = appContext;
        this.c = mEventLogger;
        this.d = mGaLogger;
        this.e = mAccessibilityServiceLogger;
        this.f = mNotificationDeviceStatus;
        this.g = notificationChannelsManager;
        this.h = mObjectMapper;
    }

    public final int a() {
        try {
            return this.b.getPackageManager().getPackageInfo("com.google.android.gms", 0).versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            timber.log.c.a.p(e);
            return -1;
        }
    }
}
