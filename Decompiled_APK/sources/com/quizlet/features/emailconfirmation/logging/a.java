package com.quizlet.features.emailconfirmation.logging;

import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.generated.enums.B;
import com.quizlet.quizletandroid.ui.common.ads.G;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 3:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 4:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            default:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
        }
    }

    public void a(B action) {
        Intrinsics.checkNotNullParameter(action, "action");
        EventLoggerExt.a(this.a, action.a(), new Z(6));
    }

    public void b(com.quizlet.quizletandroid.ui.setcreation.tracking.a event) {
        Intrinsics.checkNotNullParameter(event, "event");
        EventLoggerExt.a(this.a, event.a, new G(event, 28));
    }
}
