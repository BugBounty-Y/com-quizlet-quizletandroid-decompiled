package com.quizlet.features.userprofile;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.ProfileNavigationEventLog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public static ProfileNavigationEventLog a(String clickName) {
        ProfileNavigationEventLog.b.getClass();
        Intrinsics.checkNotNullParameter("profile", "screenName");
        Intrinsics.checkNotNullParameter(clickName, "clickName");
        Intrinsics.checkNotNullParameter("profile", "location");
        Intrinsics.checkNotNullParameter("click", "action");
        ProfileNavigationEventLog profileNavigationEventLog = new ProfileNavigationEventLog(new ProfileNavigationEventLog.Payload("profile", clickName, "profile"));
        profileNavigationEventLog.setAction("click");
        return profileNavigationEventLog;
    }
}
