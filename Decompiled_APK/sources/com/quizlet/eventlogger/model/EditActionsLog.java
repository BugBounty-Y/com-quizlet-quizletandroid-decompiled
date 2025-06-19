package com.quizlet.eventlogger.model;

import android.os.Parcel;
import android.os.Parcelable;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class EditActionsLog extends StandardizedEventLog implements Parcelable {

    @NotNull
    private final EditActionsPayload payload;
    public static final Companion b = new Companion(null);

    @NotNull
    public static final Parcelable.Creator<EditActionsLog> CREATOR = new Creator();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Creator implements Parcelable.Creator<EditActionsLog> {
        @Override // android.os.Parcelable.Creator
        public final EditActionsLog createFromParcel(Parcel parcel) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            return new EditActionsLog(EditActionsPayload.CREATOR.createFromParcel(parcel));
        }

        @Override // android.os.Parcelable.Creator
        public final EditActionsLog[] newArray(int i) {
            return new EditActionsLog[i];
        }
    }

    @Metadata
    public static final class EditActionsPayload extends StandardizedPayloadBase implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<EditActionsPayload> CREATOR = new Creator();
        private Long clientModelId;
        private String editSessionId;
        private Integer editTimeSec;
        private String inputMethod;
        private Integer modelType;
        private Integer numberOfEdits;
        private Boolean predictionModified;
        private String predictionRequestUuid;
        private Integer predictionSelectionDepth;
        private Long predictionSelectionId;
        private Long serverModelId;
        private Boolean usedPrediction;

        @Metadata
        public static final class Creator implements Parcelable.Creator<EditActionsPayload> {
            @Override // android.os.Parcelable.Creator
            public final EditActionsPayload createFromParcel(Parcel parcel) {
                Boolean boolValueOf;
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                String string = parcel.readString();
                String string2 = parcel.readString();
                Boolean boolValueOf2 = null;
                Integer numValueOf = parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt());
                Integer numValueOf2 = parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt());
                Long lValueOf = parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong());
                Long lValueOf2 = parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong());
                Integer numValueOf3 = parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt());
                if (parcel.readInt() == 0) {
                    boolValueOf = null;
                } else {
                    boolValueOf = Boolean.valueOf(parcel.readInt() != 0);
                }
                String string3 = parcel.readString();
                Integer numValueOf4 = parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt());
                Long lValueOf3 = parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong());
                if (parcel.readInt() != 0) {
                    boolValueOf2 = Boolean.valueOf(parcel.readInt() != 0);
                }
                return new EditActionsPayload(string, string2, numValueOf, numValueOf2, lValueOf, lValueOf2, numValueOf3, boolValueOf, string3, numValueOf4, lValueOf3, boolValueOf2);
            }

            @Override // android.os.Parcelable.Creator
            public final EditActionsPayload[] newArray(int i) {
                return new EditActionsPayload[i];
            }
        }

        public EditActionsPayload() {
            this(null, null, null, null, null, null, null, null, null, null, null, null, 4095, null);
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @JsonProperty("client_model_id")
        public final Long getClientModelId() {
            return this.clientModelId;
        }

        @JsonProperty("edit_session_id")
        public final String getEditSessionId() {
            return this.editSessionId;
        }

        @JsonProperty("edit_time_sec")
        public final Integer getEditTimeSec() {
            return this.editTimeSec;
        }

        @JsonProperty("input_method")
        public final String getInputMethod() {
            return this.inputMethod;
        }

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        public final Integer getModelType() {
            return this.modelType;
        }

        @JsonProperty("number_of_edits")
        public final Integer getNumberOfEdits() {
            return this.numberOfEdits;
        }

        @JsonProperty("prediction_modified")
        public final Boolean getPredictionModified() {
            return this.predictionModified;
        }

        @JsonProperty("prediction_request_uuid")
        public final String getPredictionRequestUuid() {
            return this.predictionRequestUuid;
        }

        @JsonProperty("prediction_selection_depth")
        public final Integer getPredictionSelectionDepth() {
            return this.predictionSelectionDepth;
        }

        @JsonProperty("prediction_selection_id")
        public final Long getPredictionSelectionId() {
            return this.predictionSelectionId;
        }

        @JsonProperty("server_model_id")
        public final Long getServerModelId() {
            return this.serverModelId;
        }

        @JsonProperty("used_prediction")
        public final Boolean getUsedPrediction() {
            return this.usedPrediction;
        }

        public final void setClientModelId(Long l) {
            this.clientModelId = l;
        }

        public final void setEditSessionId(String str) {
            this.editSessionId = str;
        }

        public final void setEditTimeSec(Integer num) {
            this.editTimeSec = num;
        }

        public final void setInputMethod(String str) {
            this.inputMethod = str;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setNumberOfEdits(Integer num) {
            this.numberOfEdits = num;
        }

        public final void setPredictionModified(Boolean bool) {
            this.predictionModified = bool;
        }

        public final void setPredictionRequestUuid(String str) {
            this.predictionRequestUuid = str;
        }

        public final void setPredictionSelectionDepth(Integer num) {
            this.predictionSelectionDepth = num;
        }

        public final void setPredictionSelectionId(Long l) {
            this.predictionSelectionId = l;
        }

        public final void setServerModelId(Long l) {
            this.serverModelId = l;
        }

        public final void setUsedPrediction(Boolean bool) {
            this.usedPrediction = bool;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.editSessionId);
            dest.writeString(this.inputMethod);
            Integer num = this.editTimeSec;
            if (num == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(num.intValue());
            }
            Integer num2 = this.numberOfEdits;
            if (num2 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(num2.intValue());
            }
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
            Integer num3 = this.modelType;
            if (num3 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(num3.intValue());
            }
            Boolean bool = this.usedPrediction;
            if (bool == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(bool.booleanValue() ? 1 : 0);
            }
            dest.writeString(this.predictionRequestUuid);
            Integer num4 = this.predictionSelectionDepth;
            if (num4 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(num4.intValue());
            }
            Long l3 = this.predictionSelectionId;
            if (l3 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeLong(l3.longValue());
            }
            Boolean bool2 = this.predictionModified;
            if (bool2 == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeInt(bool2.booleanValue() ? 1 : 0);
            }
        }

        public /* synthetic */ EditActionsPayload(String str, String str2, Integer num, Integer num2, Long l, Long l2, Integer num3, Boolean bool, String str3, Integer num4, Long l3, Boolean bool2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : num, (i & 8) != 0 ? null : num2, (i & 16) != 0 ? null : l, (i & 32) != 0 ? null : l2, (i & 64) != 0 ? null : num3, (i & 128) != 0 ? null : bool, (i & 256) != 0 ? null : str3, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : num4, (i & 1024) != 0 ? null : l3, (i & 2048) != 0 ? null : bool2);
        }

        public EditActionsPayload(String str, String str2, Integer num, Integer num2, Long l, Long l2, Integer num3, Boolean bool, String str3, Integer num4, Long l3, Boolean bool2) {
            this.editSessionId = str;
            this.inputMethod = str2;
            this.editTimeSec = num;
            this.numberOfEdits = num2;
            this.clientModelId = l;
            this.serverModelId = l2;
            this.modelType = num3;
            this.usedPrediction = bool;
            this.predictionRequestUuid = str3;
            this.predictionSelectionDepth = num4;
            this.predictionSelectionId = l3;
            this.predictionModified = bool2;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public EditActionsLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final void c(int i) {
        if (getPayload().getEditTimeSec() == null) {
            getPayload().setEditTimeSec(0);
        }
        EditActionsPayload payload = getPayload();
        Integer editTimeSec = getPayload().getEditTimeSec();
        payload.setEditTimeSec(editTimeSec != null ? Integer.valueOf(editTimeSec.intValue() + i) : null);
    }

    public final void d() {
        if (getPayload().getNumberOfEdits() == null) {
            getPayload().setNumberOfEdits(0);
        }
        EditActionsPayload payload = getPayload();
        Integer numberOfEdits = getPayload().getNumberOfEdits();
        payload.setNumberOfEdits(numberOfEdits != null ? Integer.valueOf(numberOfEdits.intValue() + 1) : null);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof EditActionsLog) && Intrinsics.b(this.payload, ((EditActionsLog) obj).payload);
    }

    public final Long getClientModelId() {
        return getPayload().getClientModelId();
    }

    public final Integer getEditTimeSec() {
        return getPayload().getEditTimeSec();
    }

    public final Integer getNumberOfEdits() {
        return getPayload().getNumberOfEdits();
    }

    public final Long getServerModelId() {
        return getPayload().getServerModelId();
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "EditActionsLog(payload=" + this.payload + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.payload.writeToParcel(dest, i);
    }

    public /* synthetic */ EditActionsLog(EditActionsPayload editActionsPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        EditActionsPayload editActionsPayload2;
        if ((i & 1) != 0) {
            editActionsPayload2 = new EditActionsPayload(null, null, null, null, null, null, null, null, null, null, null, null, 4095, null);
        } else {
            editActionsPayload2 = editActionsPayload;
        }
        this(editActionsPayload2);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @JsonProperty("payload")
    @NotNull
    public EditActionsPayload getPayload() {
        return this.payload;
    }

    public EditActionsLog(@NotNull EditActionsPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.EDIT_ACTIONS);
    }
}
