package com.quizlet.eventlogger.features.studymodes;

import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.StudyEventLog;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import java.util.UUID;

/* loaded from: classes2.dex */
public class StudyModeEventLogger {
    public final EventLogger a;
    public final A1 b;

    public static class Factory {
        private final EventLogger eventLogger;

        public Factory(EventLogger eventLogger) {
            this.eventLogger = eventLogger;
        }

        public final StudyModeEventLogger a(A1 a1) {
            return new StudyModeEventLogger(this.eventLogger, a1);
        }
    }

    public StudyModeEventLogger(EventLogger eventLogger, A1 a1) {
        this.a = eventLogger;
        this.b = a1;
    }

    public final StudyEventLog a(String str, String str2, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, Boolean bool, String str3, Boolean bool2) {
        Long lValueOf = (dBSession == null || dBSession.getId() <= 0) ? null : Long.valueOf(dBSession.getId());
        Long lValueOf2 = dBSession != null ? Long.valueOf(dBSession.getLocalId()) : null;
        Long l3 = (l == null || l.longValue() < 0) ? null : l;
        long jLongValue = l2.longValue();
        boolean zBooleanValue = bool.booleanValue();
        StudyEventLog.b.getClass();
        return StudyEventLog.Companion.a(str, str2, this.b, lValueOf, lValueOf2, l3, jLongValue, g1, zBooleanValue, num, str3, null, null, null, null, bool2);
    }

    public final void b(String str, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, boolean z, String str2, Boolean bool) {
        this.a.v(StudyEventLog.c("begin", str, this.b, (dBSession == null || dBSession.getId() <= 0) ? null : Long.valueOf(dBSession.getId()), dBSession != null ? Long.valueOf(dBSession.getLocalId()) : null, l.longValue() < 0 ? null : l, l2.longValue(), g1, z, num, null, null, str2, bool));
    }

    public final void c(String str, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, boolean z, String str2, UUID uuid) {
        this.a.v(StudyEventLog.c("enter", str, this.b, (dBSession == null || dBSession.getId() <= 0) ? null : Long.valueOf(dBSession.getId()), dBSession != null ? Long.valueOf(dBSession.getLocalId()) : null, l.longValue() < 0 ? null : l, l2.longValue(), g1, z, num, str2, uuid, null, null));
    }

    public final void d(String str, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, boolean z, String str2) {
        this.a.v(StudyEventLog.c("exit", str, this.b, (dBSession == null || dBSession.getId() <= 0) ? null : Long.valueOf(dBSession.getId()), dBSession != null ? Long.valueOf(dBSession.getLocalId()) : null, l.longValue() < 0 ? null : l, l2.longValue(), g1, z, num, str2, null, null, null));
    }

    public final void e(String str, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, Boolean bool, String str2, Boolean bool2) {
        this.a.v(a("enter_screen", str, g1, num, dBSession, l, l2, bool, str2, bool2));
    }

    public final void f(String str, G1 g1, Integer num, DBSession dBSession, Long l, Long l2, Boolean bool, String str2) {
        this.a.v(a("exit_screen", str, g1, num, dBSession, l, l2, bool, str2, null));
    }
}
