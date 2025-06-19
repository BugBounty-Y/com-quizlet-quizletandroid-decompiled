package com.quizlet.eventlogger.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class EditSessionsLog extends StandardizedEventLog implements Parcelable {

    @NotNull
    private final EditSessionsPayload payload;
    public static final Companion b = new Companion(null);

    @NotNull
    public static final Parcelable.Creator<EditSessionsLog> CREATOR = new Creator();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Creator implements Parcelable.Creator<EditSessionsLog> {
        @Override // android.os.Parcelable.Creator
        public final EditSessionsLog createFromParcel(Parcel parcel) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            return new EditSessionsLog(EditSessionsPayload.CREATOR.createFromParcel(parcel));
        }

        @Override // android.os.Parcelable.Creator
        public final EditSessionsLog[] newArray(int i) {
            return new EditSessionsLog[i];
        }
    }

    @Metadata
    public static final class EditSessionsPayload extends StandardizedPayloadBase implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<EditSessionsPayload> CREATOR = new Creator();
        private Long clientEndTimestamp;
        private Long clientModelId;
        private Long clientStartTimestamp;
        private String editSessionId;
        private String editSource;
        private String endType;
        private Integer modelType;
        private Long serverModelId;
        private String version;

        @Metadata
        public static final class Creator implements Parcelable.Creator<EditSessionsPayload> {
            @Override // android.os.Parcelable.Creator
            public final EditSessionsPayload createFromParcel(Parcel parcel) {
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new EditSessionsPayload(parcel.readString(), parcel.readString(), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt()), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() != 0 ? Long.valueOf(parcel.readLong()) : null, parcel.readString(), parcel.readString());
            }

            @Override // android.os.Parcelable.Creator
            public final EditSessionsPayload[] newArray(int i) {
                return new EditSessionsPayload[i];
            }
        }

        public EditSessionsPayload() {
            this(null, null, null, null, null, null, null, null, null, 511, null);
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof EditSessionsPayload)) {
                return false;
            }
            EditSessionsPayload editSessionsPayload = (EditSessionsPayload) obj;
            return Intrinsics.b(this.editSessionId, editSessionsPayload.editSessionId) && Intrinsics.b(this.editSource, editSessionsPayload.editSource) && Intrinsics.b(this.clientModelId, editSessionsPayload.clientModelId) && Intrinsics.b(this.serverModelId, editSessionsPayload.serverModelId) && Intrinsics.b(this.modelType, editSessionsPayload.modelType) && Intrinsics.b(this.clientStartTimestamp, editSessionsPayload.clientStartTimestamp) && Intrinsics.b(this.clientEndTimestamp, editSessionsPayload.clientEndTimestamp) && Intrinsics.b(this.endType, editSessionsPayload.endType) && Intrinsics.b(this.version, editSessionsPayload.version);
        }

        @JsonProperty("client_end_timestamp")
        public final Long getClientEndTimestamp() {
            return this.clientEndTimestamp;
        }

        @JsonProperty("client_model_id")
        public final Long getClientModelId() {
            return this.clientModelId;
        }

        @JsonProperty("client_start_timestamp")
        public final Long getClientStartTimestamp() {
            return this.clientStartTimestamp;
        }

        @JsonProperty("edit_session_id")
        public final String getEditSessionId() {
            return this.editSessionId;
        }

        @JsonProperty("edit_source")
        public final String getEditSource() {
            return this.editSource;
        }

        @JsonProperty("end_type")
        public final String getEndType() {
            return this.endType;
        }

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        public final Integer getModelType() {
            return this.modelType;
        }

        @JsonProperty("server_model_id")
        public final Long getServerModelId() {
            return this.serverModelId;
        }

        @JsonProperty("version")
        public final String getVersion() {
            return this.version;
        }

        public final int hashCode() {
            String str = this.editSessionId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.editSource;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Long l = this.clientModelId;
            int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
            Long l2 = this.serverModelId;
            int iHashCode4 = (iHashCode3 + (l2 == null ? 0 : l2.hashCode())) * 31;
            Integer num = this.modelType;
            int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
            Long l3 = this.clientStartTimestamp;
            int iHashCode6 = (iHashCode5 + (l3 == null ? 0 : l3.hashCode())) * 31;
            Long l4 = this.clientEndTimestamp;
            int iHashCode7 = (iHashCode6 + (l4 == null ? 0 : l4.hashCode())) * 31;
            String str3 = this.endType;
            int iHashCode8 = (iHashCode7 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.version;
            return iHashCode8 + (str4 != null ? str4.hashCode() : 0);
        }

        public final void setClientEndTimestamp(Long l) {
            this.clientEndTimestamp = l;
        }

        public final void setClientModelId(Long l) {
            this.clientModelId = l;
        }

        public final void setClientStartTimestamp(Long l) {
            this.clientStartTimestamp = l;
        }

        public final void setEditSessionId(String str) {
            this.editSessionId = str;
        }

        public final void setEditSource(String str) {
            this.editSource = str;
        }

        public final void setEndType(String str) {
            this.endType = str;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setServerModelId(Long l) {
            this.serverModelId = l;
        }

        public final void setVersion(String str) {
            this.version = str;
        }

        public final String toString() {
            String str = this.editSessionId;
            String str2 = this.editSource;
            Long l = this.clientModelId;
            Long l2 = this.serverModelId;
            Integer num = this.modelType;
            Long l3 = this.clientStartTimestamp;
            Long l4 = this.clientEndTimestamp;
            String str3 = this.endType;
            String str4 = this.version;
            StringBuilder sbH = AbstractC0147y.h("EditSessionsPayload(editSessionId=", str, ", editSource=", str2, ", clientModelId=");
            sbH.append(l);
            sbH.append(", serverModelId=");
            sbH.append(l2);
            sbH.append(", modelType=");
            sbH.append(num);
            sbH.append(", clientStartTimestamp=");
            sbH.append(l3);
            sbH.append(", clientEndTimestamp=");
            sbH.append(l4);
            sbH.append(", endType=");
            sbH.append(str3);
            sbH.append(", version=");
            return a.t(sbH, str4, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.editSessionId);
            dest.writeString(this.editSource);
            Long l = this.clientModelId;
            if (l == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeLong(l.longValue());
            }
            Long l2 = this.serverModelId;
            if (l2 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeLong(l2.longValue());
            }
            Integer num = this.modelType;
            if (num == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(num.intValue());
            }
            Long l3 = this.clientStartTimestamp;
            if (l3 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeLong(l3.longValue());
            }
            Long l4 = this.clientEndTimestamp;
            if (l4 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeLong(l4.longValue());
            }
            dest.writeString(this.endType);
            dest.writeString(this.version);
        }

        public /* synthetic */ EditSessionsPayload(String str, String str2, Long l, Long l2, Integer num, Long l3, Long l4, String str3, String str4, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : l2, (i & 16) != 0 ? null : num, (i & 32) != 0 ? null : l3, (i & 64) != 0 ? null : l4, (i & 128) != 0 ? null : str3, (i & 256) != 0 ? null : str4);
        }

        public EditSessionsPayload(String str, String str2, Long l, Long l2, Integer num, Long l3, Long l4, String str3, String str4) {
            this.editSessionId = str;
            this.editSource = str2;
            this.clientModelId = l;
            this.serverModelId = l2;
            this.modelType = num;
            this.clientStartTimestamp = l3;
            this.clientEndTimestamp = l4;
            this.endType = str3;
            this.version = str4;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public EditSessionsLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final void c() {
        getPayload().setClientEndTimestamp(Long.valueOf(assistantMode.refactored.a.f() / 1000));
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof EditSessionsLog) && Intrinsics.b(this.payload, ((EditSessionsLog) obj).payload);
    }

    public final String getEndType() {
        return getPayload().getEndType();
    }

    public final String getSessionId() {
        return getPayload().getEditSessionId();
    }

    public final String getVersion() {
        return getPayload().getVersion();
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final void setClientModelId(Long l) {
        getPayload().setClientModelId(l);
    }

    public final void setEditSetAction(@NotNull String action) {
        Intrinsics.checkNotNullParameter(action, "action");
        setAction(action);
    }

    public final void setEndtype(@NotNull String endType) {
        Intrinsics.checkNotNullParameter(endType, "endType");
        getPayload().setEndType(endType);
        c();
    }

    public final void setServerModelId(Long l) {
        getPayload().setServerModelId(l);
    }

    public final String toString() {
        return "EditSessionsLog(payload=" + this.payload + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.payload.writeToParcel(dest, i);
    }

    public /* synthetic */ EditSessionsLog(EditSessionsPayload editSessionsPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        if ((i & 1) != 0) {
            editSessionsPayload = new EditSessionsPayload(null, null, null, null, null, null, null, null, null, 511, null);
        }
        this(editSessionsPayload);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @JsonProperty("payload")
    @NotNull
    public EditSessionsPayload getPayload() {
        return this.payload;
    }

    public EditSessionsLog(@NotNull EditSessionsPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.EDIT_SESSIONS);
    }
}
