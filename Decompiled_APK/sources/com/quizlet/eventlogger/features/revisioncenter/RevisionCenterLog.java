package com.quizlet.eventlogger.features.revisioncenter;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class RevisionCenterLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("source")
        private String source;

        @JsonProperty(DBUserFields.Names.USER_UPGRADE_TYPE)
        private String type;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.type, payload.type) && Intrinsics.b(this.source, payload.source);
        }

        public final String getSource() {
            return this.source;
        }

        public final String getType() {
            return this.type;
        }

        public final int hashCode() {
            String str = this.type;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.source;
            return iHashCode + (str2 != null ? str2.hashCode() : 0);
        }

        public final void setSource(String str) {
            this.source = str;
        }

        public final void setType(String str) {
            this.type = str;
        }

        public final String toString() {
            return AbstractC0147y.e("Payload(type=", this.type, ", source=", this.source, ")");
        }

        public /* synthetic */ Payload(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2);
        }

        public Payload(String str, String str2) {
            this.type = str;
            this.source = str2;
        }
    }

    public RevisionCenterLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
