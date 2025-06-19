package com.quizlet.quizletandroid.ui.globalnav.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.home.HomeEventLog;
import com.quizlet.generated.enums.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(String str, String str2, String str3) {
        this.a.l(HomeEventLog.Companion.b(HomeEventLog.b, str2, str3, str, U.CLICK.a(), null, 496));
    }
}
