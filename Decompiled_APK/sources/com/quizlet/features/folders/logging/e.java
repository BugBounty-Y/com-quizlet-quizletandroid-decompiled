package com.quizlet.features.folders.logging;

import androidx.collection.C0208f;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3514p4;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.generated.enums.y1;
import java.util.LinkedHashSet;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final EventLogger a;
    public final StudyFunnelEventLogger b;
    public final com.quizlet.infra.contracts.studyfunnel.a c;
    public UUID d;
    public final LinkedHashSet e;

    public e(EventLogger eventLogger, StudyFunnelEventLogger studyFunnelEventLogger, com.quizlet.infra.contracts.studyfunnel.a studyFunnelEventManager) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(studyFunnelEventLogger, "studyFunnelEventLogger");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        this.a = eventLogger;
        this.b = studyFunnelEventLogger;
        this.c = studyFunnelEventManager;
        this.e = new LinkedHashSet();
    }

    public static void b(e eVar, long j, String str, String str2, String str3, y1 y1Var, String str4, Function1 function1, int i) {
        boolean z = (i & 4) != 0;
        if ((i & 8) != 0) {
            str2 = "";
        }
        if ((i & 16) != 0) {
            str3 = null;
        }
        if ((i & 32) != 0) {
            y1Var = null;
        }
        if ((i & 64) != 0) {
            str4 = EnumC4525u1.FOLDER_PAGE.a();
        }
        if ((i & 128) != 0) {
            function1 = new C4237k(9);
        }
        eVar.getClass();
        NavigationEventLog.b.getClass();
        NavigationEventLog navigationEventLogA = NavigationEventLog.Companion.a(z, str4, str, "info", str2);
        navigationEventLogA.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogA.getPayload().c(y1Var != null ? Integer.valueOf(y1Var.b()) : null, str3);
        function1.invoke(navigationEventLogA.getPayload());
        eVar.a.l(navigationEventLogA);
    }

    public static int e(f fVar) {
        y1 y1Var = fVar.c;
        switch (y1Var == null ? -1 : d.a[y1Var.ordinal()]) {
            case -1:
            case 7:
            case 8:
                return 0;
            case 0:
            default:
                throw new NoWhenBranchMatchedException();
            case 1:
                return 1;
            case 2:
                return 20;
            case 3:
                return 3;
            case 4:
                return 14;
            case 5:
                return 15;
            case 6:
                return 16;
        }
    }

    public final UUID a(String str) {
        UUID uuidRandomUUID;
        UUID uuid = this.d;
        if (uuid != null) {
            return uuid;
        }
        C0208f c0208fB = ((com.quizlet.features.infra.basestudy.manager.d) this.c).b(3);
        if (c0208fB == null) {
            uuidRandomUUID = UUID.randomUUID();
            Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID(...)");
        } else {
            Object objRandomUUID = c0208fB.get(str);
            if (objRandomUUID == null) {
                objRandomUUID = UUID.randomUUID();
                c0208fB.put(str, objRandomUUID);
            }
            Intrinsics.d(objRandomUUID);
            uuidRandomUUID = (UUID) objRandomUUID;
        }
        this.d = uuidRandomUUID;
        return uuidRandomUUID;
    }

    public final void c(f data) {
        Intrinsics.checkNotNullParameter(data, "data");
        EnumC4519s1 enumC4519s1 = EnumC4519s1.CLICK;
        String str = data.b;
        int iE = e(data);
        UUID uuidA = a(String.valueOf(data.a));
        EnumC4525u1 enumC4525u1 = EnumC4525u1.FOLDER_PAGE;
        w1 w1Var = data.d ? w1.COURSE_FOLDER_RECOMMENDATION : data.g ? w1.ADD_TO_FOLDER : w1.FOLDER_SECTION;
        Integer num = data.e;
        StudyFunnelEventLogger.a(this.b, enumC4519s1, null, iE, uuidA, enumC4525u1, w1Var, 0, num != null ? num.intValue() : 0, null, null, str, new b(data, 1), 770);
    }

    public final void d(f data) {
        Intrinsics.checkNotNullParameter(data, "data");
        LinkedHashSet linkedHashSet = this.e;
        if (linkedHashSet.contains(data)) {
            return;
        }
        linkedHashSet.add(data);
        int iE = e(data);
        EnumC4525u1 enumC4525u1 = EnumC4525u1.FOLDER_PAGE;
        w1 w1Var = data.d ? w1.COURSE_FOLDER_RECOMMENDATION : data.g ? w1.ADD_TO_FOLDER : w1.FOLDER_SECTION;
        Integer num = data.e;
        int iIntValue = num != null ? num.intValue() : 0;
        long j = data.a;
        AbstractC3514p4.a(this.c, null, iE, enumC4525u1, w1Var, 0, iIntValue, null, data.b, a(String.valueOf(j)), Long.valueOf(j), data.f, 65);
    }
}
