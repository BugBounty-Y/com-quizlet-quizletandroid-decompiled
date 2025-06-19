package com.quizlet.quizletandroid.ui.startpage.nav2.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.home.HomeEventLog;
import com.quizlet.generated.enums.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final EventLogger a;

    public c(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public static void a(c cVar, String str) {
        cVar.getClass();
        cVar.a.l(HomeEventLog.Companion.b(HomeEventLog.b, "Homepage", "bottom_nav", str, U.CLICK.a(), null, 496));
    }
}
