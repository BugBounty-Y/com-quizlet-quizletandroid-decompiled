package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class UniversalUploadFlowEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static UniversalUploadFlowEventLog a(EnumC4503n table, String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(table, "table");
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(action, null, null, null, null, null, null, null, null, null, null, 2046, null);
            payloadModifier.invoke(payload);
            UniversalUploadFlowEventLog universalUploadFlowEventLog = new UniversalUploadFlowEventLog(payload);
            universalUploadFlowEventLog.setTable(table);
            universalUploadFlowEventLog.setAction(action);
            return universalUploadFlowEventLog;
        }

        public static /* synthetic */ UniversalUploadFlowEventLog b(Companion companion, EnumC4503n enumC4503n, String str) {
            Z z = new Z(24);
            companion.getClass();
            return a(enumC4503n, str, z);
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("action_name")
        private String actionName;

        @JsonProperty("char_count")
        private Integer charCount;

        @JsonProperty("error")
        private String error;

        @JsonProperty("file_types")
        private List<String> fileTypes;

        @JsonProperty("input_type")
        private String inputType;

        @JsonProperty("public_visibility")
        private Boolean isVisible;

        @JsonProperty("note_id")
        private String noteId;

        @JsonProperty("question_bank_id")
        private String questionBankId;

        @JsonProperty("screen")
        @NotNull
        private String screen;

        @JsonProperty("set_id")
        private Long setId;

        @JsonProperty("tabSelected")
        private String tabSelected;

        public Payload() {
            this(null, null, null, null, null, null, null, null, null, null, null, 2047, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.actionName, payload.actionName) && Intrinsics.b(this.noteId, payload.noteId) && Intrinsics.b(this.questionBankId, payload.questionBankId) && Intrinsics.b(this.isVisible, payload.isVisible) && Intrinsics.b(this.charCount, payload.charCount) && Intrinsics.b(this.fileTypes, payload.fileTypes) && Intrinsics.b(this.inputType, payload.inputType) && Intrinsics.b(this.tabSelected, payload.tabSelected) && Intrinsics.b(this.error, payload.error) && Intrinsics.b(this.setId, payload.setId) && Intrinsics.b(this.screen, payload.screen);
        }

        public final String getActionName() {
            return this.actionName;
        }

        public final Integer getCharCount() {
            return this.charCount;
        }

        public final String getError() {
            return this.error;
        }

        public final List<String> getFileTypes() {
            return this.fileTypes;
        }

        public final String getInputType() {
            return this.inputType;
        }

        public final String getNoteId() {
            return this.noteId;
        }

        public final String getQuestionBankId() {
            return this.questionBankId;
        }

        @NotNull
        public final String getScreen() {
            return this.screen;
        }

        public final Long getSetId() {
            return this.setId;
        }

        public final String getTabSelected() {
            return this.tabSelected;
        }

        public final int hashCode() {
            String str = this.actionName;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.noteId;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.questionBankId;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Boolean bool = this.isVisible;
            int iHashCode4 = (iHashCode3 + (bool == null ? 0 : bool.hashCode())) * 31;
            Integer num = this.charCount;
            int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
            List<String> list = this.fileTypes;
            int iHashCode6 = (iHashCode5 + (list == null ? 0 : list.hashCode())) * 31;
            String str4 = this.inputType;
            int iHashCode7 = (iHashCode6 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.tabSelected;
            int iHashCode8 = (iHashCode7 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.error;
            int iHashCode9 = (iHashCode8 + (str6 == null ? 0 : str6.hashCode())) * 31;
            Long l = this.setId;
            return this.screen.hashCode() + ((iHashCode9 + (l != null ? l.hashCode() : 0)) * 31);
        }

        public final void setActionName(String str) {
            this.actionName = str;
        }

        public final void setCharCount(Integer num) {
            this.charCount = num;
        }

        public final void setError(String str) {
            this.error = str;
        }

        public final void setFileTypes(List<String> list) {
            this.fileTypes = list;
        }

        public final void setInputType(String str) {
            this.inputType = str;
        }

        public final void setNoteId(String str) {
            this.noteId = str;
        }

        public final void setQuestionBankId(String str) {
            this.questionBankId = str;
        }

        public final void setScreen(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.screen = str;
        }

        public final void setSetId(Long l) {
            this.setId = l;
        }

        public final void setTabSelected(String str) {
            this.tabSelected = str;
        }

        public final void setVisible(Boolean bool) {
            this.isVisible = bool;
        }

        public final String toString() {
            String str = this.actionName;
            String str2 = this.noteId;
            String str3 = this.questionBankId;
            Boolean bool = this.isVisible;
            Integer num = this.charCount;
            List<String> list = this.fileTypes;
            String str4 = this.inputType;
            String str5 = this.tabSelected;
            String str6 = this.error;
            Long l = this.setId;
            String str7 = this.screen;
            StringBuilder sbH = AbstractC0147y.h("Payload(actionName=", str, ", noteId=", str2, ", questionBankId=");
            sbH.append(str3);
            sbH.append(", isVisible=");
            sbH.append(bool);
            sbH.append(", charCount=");
            sbH.append(num);
            sbH.append(", fileTypes=");
            sbH.append(list);
            sbH.append(", inputType=");
            B.u(sbH, str4, ", tabSelected=", str5, ", error=");
            sbH.append(str6);
            sbH.append(", setId=");
            sbH.append(l);
            sbH.append(", screen=");
            return a.t(sbH, str7, ")");
        }

        public /* synthetic */ Payload(String str, String str2, String str3, Boolean bool, Integer num, List list, String str4, String str5, String str6, Long l, String str7, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : bool, (i & 16) != 0 ? null : num, (i & 32) != 0 ? null : list, (i & 64) != 0 ? null : str4, (i & 128) != 0 ? null : str5, (i & 256) != 0 ? null : str6, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : l, (i & 1024) != 0 ? "upload_content" : str7);
        }

        public Payload(String str, String str2, String str3, Boolean bool, Integer num, List<String> list, String str4, String str5, String str6, Long l, @NotNull String screen) {
            Intrinsics.checkNotNullParameter(screen, "screen");
            this.actionName = str;
            this.noteId = str2;
            this.questionBankId = str3;
            this.isVisible = bool;
            this.charCount = num;
            this.fileTypes = list;
            this.inputType = str4;
            this.tabSelected = str5;
            this.error = str6;
            this.setId = l;
            this.screen = screen;
        }
    }

    public UniversalUploadFlowEventLog(@NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UniversalUploadFlowEventLog) && Intrinsics.b(this.payload, ((UniversalUploadFlowEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "UniversalUploadFlowEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
