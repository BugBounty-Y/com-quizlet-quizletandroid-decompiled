package com.quizlet.quizletandroid.ui.startpage.nav2.logging;

import com.amazon.device.ads.DtbConstants;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.home.HomeEventLog;
import com.quizlet.generated.enums.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final String b = U.CLICK.a();
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public static void b(a aVar, String str, String str2, String str3, int i) {
        String str4;
        aVar.getClass();
        HomeEventLog.Companion companion = HomeEventLog.b;
        if (i == 1) {
            str4 = "QSet";
        } else if (i == 3) {
            str4 = "QFolder";
        } else if (i == 5) {
            str4 = "QSchool";
        } else if (i == 20) {
            str4 = "Note";
        } else if (i != 9999) {
            switch (i) {
                case 13:
                    str4 = "QCourse";
                    break;
                case 14:
                    str4 = "Textbook";
                    break;
                case 15:
                    str4 = "Exercise";
                    break;
                case 16:
                    str4 = "ExplanationsQuestion";
                    break;
                default:
                    str4 = null;
                    break;
            }
        } else {
            str4 = "QClass";
        }
        String str5 = str4;
        companion.getClass();
        aVar.a.l(HomeEventLog.Companion.a("LoggedInHomepage", "logged_in_home", str, b, str2, str3, str5, null));
    }

    public final void a(String str, String str2) {
        this.a.l(HomeEventLog.Companion.b(HomeEventLog.b, "LoggedInHomepage", "logged_in_home", str, b, str2, DtbConstants.DEFAULT_PLAYER_HEIGHT));
    }
}
