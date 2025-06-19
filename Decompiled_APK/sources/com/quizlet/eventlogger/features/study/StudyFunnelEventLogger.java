package com.quizlet.eventlogger.features.study;

import com.google.android.gms.ads.g;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.StudyFunnelEventLog;
import com.quizlet.generated.enums.EnumC4502m1;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.F;
import com.quizlet.generated.enums.w1;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyFunnelEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public StudyFunnelEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public static void a(StudyFunnelEventLogger studyFunnelEventLogger, EnumC4519s1 action, Long l, int i, UUID funnelID, EnumC4525u1 placement, w1 w1Var, int i2, int i3, F f, String str, String str2, Function1 function1, int i4) {
        String str3;
        String string;
        Long l2 = (i4 & 2) != 0 ? null : l;
        F f2 = (i4 & 256) != 0 ? null : f;
        String str4 = (i4 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str;
        if ((i4 & 1024) != 0) {
            if (l2 == null || (string = l2.toString()) == null) {
                string = str4;
            }
            str3 = string;
        } else {
            str3 = str2;
        }
        Function1 modifier = (i4 & 2048) != 0 ? new Z(21) : function1;
        studyFunnelEventLogger.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(funnelID, "funnelID");
        Intrinsics.checkNotNullParameter(placement, "placement");
        Intrinsics.checkNotNullParameter(modifier, "modifier");
        EnumC4502m1 enumC4502m1 = w1Var == w1.BEHAVIORAL_REC ? EnumC4502m1.MERGED_USER_BASED_AND_ITEM_TO_ITEM : null;
        StudyFunnelEventLog.Companion companion = StudyFunnelEventLog.b;
        Integer numValueOf = Integer.valueOf(i2);
        Integer numValueOf2 = Integer.valueOf(i3);
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        EnumC4502m1 enumC4502m12 = enumC4502m1;
        StudyFunnelEventLog studyFunnelEventLog = new StudyFunnelEventLog(new StudyFunnelEventLog.Payload(action.a(), i, l2, String.valueOf(funnelID), placement != null ? placement.a() : null, w1Var != null ? w1Var.a() : null, numValueOf, numValueOf2, enumC4502m12 != null ? Integer.valueOf(enumC4502m12.a()) : null, f2 != null ? f2.a() : null, str4, str3, null, null, 12288, null));
        studyFunnelEventLog.setAction(action.a());
        modifier.invoke(studyFunnelEventLog);
        studyFunnelEventLogger.eventLogger.v(studyFunnelEventLog);
    }

    @NotNull
    public final EventLogger getEventLogger() {
        return this.eventLogger;
    }
}
