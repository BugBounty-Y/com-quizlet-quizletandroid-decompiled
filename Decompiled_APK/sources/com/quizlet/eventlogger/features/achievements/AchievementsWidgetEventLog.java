package com.quizlet.eventlogger.features.achievements;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsWidgetEventLog extends StandardizedEventLog {

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("destination")
        private String destination;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Payload) && Intrinsics.b(this.destination, ((Payload) obj).destination);
        }

        public final String getDestination() {
            return this.destination;
        }

        public final int hashCode() {
            String str = this.destination;
            if (str == null) {
                return 0;
            }
            return str.hashCode();
        }

        public final void setDestination(String str) {
            this.destination = str;
        }

        public final String toString() {
            return android.support.v4.media.session.a.B("Payload(destination=", this.destination, ")");
        }

        public /* synthetic */ Payload(String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str);
        }

        public Payload(String str) {
            this.destination = str;
        }
    }

    public AchievementsWidgetEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof AchievementsWidgetEventLog) && Intrinsics.b(this.payload, ((AchievementsWidgetEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "AchievementsWidgetEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
