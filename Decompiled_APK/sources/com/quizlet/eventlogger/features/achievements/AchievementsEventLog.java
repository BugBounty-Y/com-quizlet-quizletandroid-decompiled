package com.quizlet.eventlogger.features.achievements;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static AchievementsEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, 1, 0 == true ? 1 : 0);
            payloadModifier.invoke(payload);
            AchievementsEventLog achievementsEventLog = new AchievementsEventLog(payload);
            achievementsEventLog.setTable(EnumC4503n.ANDROID_EVENTS);
            achievementsEventLog.setAction(action);
            return achievementsEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("badgeId")
        private String badgeId;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Payload) && Intrinsics.b(this.badgeId, ((Payload) obj).badgeId);
        }

        public final String getBadgeId() {
            return this.badgeId;
        }

        public final int hashCode() {
            String str = this.badgeId;
            if (str == null) {
                return 0;
            }
            return str.hashCode();
        }

        public final void setBadgeId(String str) {
            this.badgeId = str;
        }

        public final String toString() {
            return android.support.v4.media.session.a.B("Payload(badgeId=", this.badgeId, ")");
        }

        public /* synthetic */ Payload(String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str);
        }

        public Payload(String str) {
            this.badgeId = str;
        }
    }

    public AchievementsEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
