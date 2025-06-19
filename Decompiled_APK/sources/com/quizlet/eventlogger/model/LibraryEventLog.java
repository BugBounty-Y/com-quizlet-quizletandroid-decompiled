package com.quizlet.eventlogger.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.appsflyer.AdRevenueScheme;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.generated.enums.U;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LibraryEventLog extends StandardizedEventLog {

    @NotNull
    private static final String SCREEN_NAME = "Library";
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static LibraryEventLog a(Companion companion, String clickName, Function1 function1, int i) {
            String action = U.CLICK.a();
            Function1 payloadModifier = (i & 8) != 0 ? new Z(22) : function1;
            companion.getClass();
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            String str = LibraryEventLog.SCREEN_NAME;
            Intrinsics.checkNotNullParameter(LibraryEventLog.SCREEN_NAME, "screenName");
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(str, clickName, null, null, null, null, null, null, null, null, null, null, null, null, 16380, null);
            payloadModifier.invoke(payload);
            LibraryEventLog libraryEventLog = new LibraryEventLog(payload);
            libraryEventLog.setAction(action);
            return libraryEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {
        private String clickCategory;

        @NotNull
        private String clickName;

        @JsonProperty("isbn")
        private String isbn;

        @JsonProperty("location")
        private String location;

        @JsonProperty("media_exercise_id")
        private String mediaExerciseId;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID)
        private Long modelId;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private Integer modelType;

        @JsonProperty("note_id")
        private String noteId;

        @JsonProperty(AdRevenueScheme.PLACEMENT)
        private String placement;

        @JsonProperty("query")
        private String query;

        @JsonProperty("question_bank_id")
        private String questionBankId;

        @JsonProperty("question_uuid")
        private String questionUuid;

        @NotNull
        private String screenName;

        @JsonProperty("set_id")
        private Long setId;

        public /* synthetic */ Payload(String str, String str2, Long l, String str3, String str4, String str5, Long l2, String str6, String str7, String str8, String str9, String str10, Integer num, String str11, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this(str, str2, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : str3, (i & 16) != 0 ? null : str4, (i & 32) != 0 ? null : str5, (i & 64) != 0 ? null : l2, (i & 128) != 0 ? null : str6, (i & 256) != 0 ? null : str7, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str8, (i & 1024) != 0 ? null : str9, (i & 2048) != 0 ? null : str10, (i & 4096) != 0 ? null : num, (i & 8192) != 0 ? null : str11);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.screenName, payload.screenName) && Intrinsics.b(this.clickName, payload.clickName) && Intrinsics.b(this.setId, payload.setId) && Intrinsics.b(this.clickCategory, payload.clickCategory) && Intrinsics.b(this.location, payload.location) && Intrinsics.b(this.placement, payload.placement) && Intrinsics.b(this.modelId, payload.modelId) && Intrinsics.b(this.noteId, payload.noteId) && Intrinsics.b(this.questionBankId, payload.questionBankId) && Intrinsics.b(this.isbn, payload.isbn) && Intrinsics.b(this.mediaExerciseId, payload.mediaExerciseId) && Intrinsics.b(this.questionUuid, payload.questionUuid) && Intrinsics.b(this.modelType, payload.modelType) && Intrinsics.b(this.query, payload.query);
        }

        public final String getClickCategory() {
            return this.clickCategory;
        }

        @NotNull
        public final String getClickName() {
            return this.clickName;
        }

        public final String getIsbn() {
            return this.isbn;
        }

        public final String getLocation() {
            return this.location;
        }

        public final String getMediaExerciseId() {
            return this.mediaExerciseId;
        }

        public final Long getModelId() {
            return this.modelId;
        }

        public final Integer getModelType() {
            return this.modelType;
        }

        public final String getNoteId() {
            return this.noteId;
        }

        public final String getPlacement() {
            return this.placement;
        }

        public final String getQuery() {
            return this.query;
        }

        public final String getQuestionBankId() {
            return this.questionBankId;
        }

        public final String getQuestionUuid() {
            return this.questionUuid;
        }

        @NotNull
        public final String getScreenName() {
            return this.screenName;
        }

        public final Long getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            int iE = d0.e(this.screenName.hashCode() * 31, 31, this.clickName);
            Long l = this.setId;
            int iHashCode = (iE + (l == null ? 0 : l.hashCode())) * 31;
            String str = this.clickCategory;
            int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.location;
            int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.placement;
            int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Long l2 = this.modelId;
            int iHashCode5 = (iHashCode4 + (l2 == null ? 0 : l2.hashCode())) * 31;
            String str4 = this.noteId;
            int iHashCode6 = (iHashCode5 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.questionBankId;
            int iHashCode7 = (iHashCode6 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.isbn;
            int iHashCode8 = (iHashCode7 + (str6 == null ? 0 : str6.hashCode())) * 31;
            String str7 = this.mediaExerciseId;
            int iHashCode9 = (iHashCode8 + (str7 == null ? 0 : str7.hashCode())) * 31;
            String str8 = this.questionUuid;
            int iHashCode10 = (iHashCode9 + (str8 == null ? 0 : str8.hashCode())) * 31;
            Integer num = this.modelType;
            int iHashCode11 = (iHashCode10 + (num == null ? 0 : num.hashCode())) * 31;
            String str9 = this.query;
            return iHashCode11 + (str9 != null ? str9.hashCode() : 0);
        }

        public final void setClickCategory(String str) {
            this.clickCategory = str;
        }

        public final void setClickName(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.clickName = str;
        }

        public final void setIsbn(String str) {
            this.isbn = str;
        }

        public final void setLocation(String str) {
            this.location = str;
        }

        public final void setMediaExerciseId(String str) {
            this.mediaExerciseId = str;
        }

        public final void setModelId(Long l) {
            this.modelId = l;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setNoteId(String str) {
            this.noteId = str;
        }

        public final void setPlacement(String str) {
            this.placement = str;
        }

        public final void setQuery(String str) {
            this.query = str;
        }

        public final void setQuestionBankId(String str) {
            this.questionBankId = str;
        }

        public final void setQuestionUuid(String str) {
            this.questionUuid = str;
        }

        public final void setScreenName(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.screenName = str;
        }

        public final void setSetId(Long l) {
            this.setId = l;
        }

        public final String toString() {
            String str = this.screenName;
            String str2 = this.clickName;
            Long l = this.setId;
            String str3 = this.clickCategory;
            String str4 = this.location;
            String str5 = this.placement;
            Long l2 = this.modelId;
            String str6 = this.noteId;
            String str7 = this.questionBankId;
            String str8 = this.isbn;
            String str9 = this.mediaExerciseId;
            String str10 = this.questionUuid;
            Integer num = this.modelType;
            String str11 = this.query;
            StringBuilder sbH = AbstractC0147y.h("Payload(screenName=", str, ", clickName=", str2, ", setId=");
            sbH.append(l);
            sbH.append(", clickCategory=");
            sbH.append(str3);
            sbH.append(", location=");
            B.u(sbH, str4, ", placement=", str5, ", modelId=");
            sbH.append(l2);
            sbH.append(", noteId=");
            sbH.append(str6);
            sbH.append(", questionBankId=");
            B.u(sbH, str7, ", isbn=", str8, ", mediaExerciseId=");
            B.u(sbH, str9, ", questionUuid=", str10, ", modelType=");
            sbH.append(num);
            sbH.append(", query=");
            sbH.append(str11);
            sbH.append(")");
            return sbH.toString();
        }

        public Payload(@JsonProperty("screen_name") @NotNull String screenName, @JsonProperty("click_name") @NotNull String clickName, Long l, @JsonProperty("click_category") String str, String str2, String str3, Long l2, String str4, String str5, String str6, String str7, String str8, Integer num, String str9) {
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            this.screenName = screenName;
            this.clickName = clickName;
            this.setId = l;
            this.clickCategory = str;
            this.location = str2;
            this.placement = str3;
            this.modelId = l2;
            this.noteId = str4;
            this.questionBankId = str5;
            this.isbn = str6;
            this.mediaExerciseId = str7;
            this.questionUuid = str8;
            this.modelType = num;
            this.query = str9;
        }
    }

    public LibraryEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.NAVIGATION_EVENTS);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LibraryEventLog) && Intrinsics.b(this.payload, ((LibraryEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "LibraryEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
