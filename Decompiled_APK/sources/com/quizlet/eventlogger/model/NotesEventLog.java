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
public final class NotesEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static NotesEventLog a(EnumC4503n table, String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(table, "table");
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(action, null, null, null, null, null, null, null, null, null, null, null, null, 8190, null);
            payloadModifier.invoke(payload);
            NotesEventLog notesEventLog = new NotesEventLog(payload);
            notesEventLog.setTable(table);
            notesEventLog.setAction(action);
            return notesEventLog;
        }

        public static /* synthetic */ NotesEventLog b(Companion companion, EnumC4503n enumC4503n, String str) {
            Z z = new Z(23);
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

        @JsonProperty("artifact_count")
        private Integer artifactCount;

        @JsonProperty("artifact_name")
        private String artifactName;

        @JsonProperty("char_count")
        private Integer charCount;

        @JsonProperty("essay_prompts")
        private Boolean essay_prompts;

        @JsonProperty("file_types")
        private List<String> fileTypes;

        @JsonProperty("flashcards")
        private Boolean flashcards;

        @JsonProperty("kotlin_error_identifier")
        private String identifier;

        @JsonProperty("input_type")
        private String inputType;

        @JsonProperty("public_visibility")
        private Boolean isVisible;

        @JsonProperty("new_title")
        private String newTitle;

        @JsonProperty("note_id")
        private String noteUuid;

        @JsonProperty("outline")
        private Boolean outline;

        public Payload() {
            this(null, null, null, null, null, null, null, null, null, null, null, null, null, 8191, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.actionName, payload.actionName) && Intrinsics.b(this.noteUuid, payload.noteUuid) && Intrinsics.b(this.isVisible, payload.isVisible) && Intrinsics.b(this.artifactName, payload.artifactName) && Intrinsics.b(this.charCount, payload.charCount) && Intrinsics.b(this.fileTypes, payload.fileTypes) && Intrinsics.b(this.inputType, payload.inputType) && Intrinsics.b(this.newTitle, payload.newTitle) && Intrinsics.b(this.outline, payload.outline) && Intrinsics.b(this.essay_prompts, payload.essay_prompts) && Intrinsics.b(this.flashcards, payload.flashcards) && Intrinsics.b(this.artifactCount, payload.artifactCount) && Intrinsics.b(this.identifier, payload.identifier);
        }

        public final String getActionName() {
            return this.actionName;
        }

        public final Integer getArtifactCount() {
            return this.artifactCount;
        }

        public final String getArtifactName() {
            return this.artifactName;
        }

        public final Integer getCharCount() {
            return this.charCount;
        }

        public final Boolean getEssay_prompts() {
            return this.essay_prompts;
        }

        public final List<String> getFileTypes() {
            return this.fileTypes;
        }

        public final Boolean getFlashcards() {
            return this.flashcards;
        }

        public final String getIdentifier() {
            return this.identifier;
        }

        public final String getInputType() {
            return this.inputType;
        }

        public final String getNewTitle() {
            return this.newTitle;
        }

        public final String getNoteUuid() {
            return this.noteUuid;
        }

        public final Boolean getOutline() {
            return this.outline;
        }

        public final int hashCode() {
            String str = this.actionName;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.noteUuid;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Boolean bool = this.isVisible;
            int iHashCode3 = (iHashCode2 + (bool == null ? 0 : bool.hashCode())) * 31;
            String str3 = this.artifactName;
            int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Integer num = this.charCount;
            int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
            List<String> list = this.fileTypes;
            int iHashCode6 = (iHashCode5 + (list == null ? 0 : list.hashCode())) * 31;
            String str4 = this.inputType;
            int iHashCode7 = (iHashCode6 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.newTitle;
            int iHashCode8 = (iHashCode7 + (str5 == null ? 0 : str5.hashCode())) * 31;
            Boolean bool2 = this.outline;
            int iHashCode9 = (iHashCode8 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
            Boolean bool3 = this.essay_prompts;
            int iHashCode10 = (iHashCode9 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
            Boolean bool4 = this.flashcards;
            int iHashCode11 = (iHashCode10 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
            Integer num2 = this.artifactCount;
            int iHashCode12 = (iHashCode11 + (num2 == null ? 0 : num2.hashCode())) * 31;
            String str6 = this.identifier;
            return iHashCode12 + (str6 != null ? str6.hashCode() : 0);
        }

        public final void setActionName(String str) {
            this.actionName = str;
        }

        public final void setArtifactCount(Integer num) {
            this.artifactCount = num;
        }

        public final void setArtifactName(String str) {
            this.artifactName = str;
        }

        public final void setCharCount(Integer num) {
            this.charCount = num;
        }

        public final void setEssay_prompts(Boolean bool) {
            this.essay_prompts = bool;
        }

        public final void setFileTypes(List<String> list) {
            this.fileTypes = list;
        }

        public final void setFlashcards(Boolean bool) {
            this.flashcards = bool;
        }

        public final void setIdentifier(String str) {
            this.identifier = str;
        }

        public final void setInputType(String str) {
            this.inputType = str;
        }

        public final void setNewTitle(String str) {
            this.newTitle = str;
        }

        public final void setNoteUuid(String str) {
            this.noteUuid = str;
        }

        public final void setOutline(Boolean bool) {
            this.outline = bool;
        }

        public final void setVisible(Boolean bool) {
            this.isVisible = bool;
        }

        public final String toString() {
            String str = this.actionName;
            String str2 = this.noteUuid;
            Boolean bool = this.isVisible;
            String str3 = this.artifactName;
            Integer num = this.charCount;
            List<String> list = this.fileTypes;
            String str4 = this.inputType;
            String str5 = this.newTitle;
            Boolean bool2 = this.outline;
            Boolean bool3 = this.essay_prompts;
            Boolean bool4 = this.flashcards;
            Integer num2 = this.artifactCount;
            String str6 = this.identifier;
            StringBuilder sbH = AbstractC0147y.h("Payload(actionName=", str, ", noteUuid=", str2, ", isVisible=");
            sbH.append(bool);
            sbH.append(", artifactName=");
            sbH.append(str3);
            sbH.append(", charCount=");
            sbH.append(num);
            sbH.append(", fileTypes=");
            sbH.append(list);
            sbH.append(", inputType=");
            B.u(sbH, str4, ", newTitle=", str5, ", outline=");
            sbH.append(bool2);
            sbH.append(", essay_prompts=");
            sbH.append(bool3);
            sbH.append(", flashcards=");
            sbH.append(bool4);
            sbH.append(", artifactCount=");
            sbH.append(num2);
            sbH.append(", identifier=");
            return a.t(sbH, str6, ")");
        }

        public /* synthetic */ Payload(String str, String str2, Boolean bool, String str3, Integer num, List list, String str4, String str5, Boolean bool2, Boolean bool3, Boolean bool4, Integer num2, String str6, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : bool, (i & 8) != 0 ? null : str3, (i & 16) != 0 ? null : num, (i & 32) != 0 ? null : list, (i & 64) != 0 ? null : str4, (i & 128) != 0 ? null : str5, (i & 256) != 0 ? null : bool2, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : bool3, (i & 1024) != 0 ? null : bool4, (i & 2048) != 0 ? null : num2, (i & 4096) != 0 ? null : str6);
        }

        public Payload(String str, String str2, Boolean bool, String str3, Integer num, List<String> list, String str4, String str5, Boolean bool2, Boolean bool3, Boolean bool4, Integer num2, String str6) {
            this.actionName = str;
            this.noteUuid = str2;
            this.isVisible = bool;
            this.artifactName = str3;
            this.charCount = num;
            this.fileTypes = list;
            this.inputType = str4;
            this.newTitle = str5;
            this.outline = bool2;
            this.essay_prompts = bool3;
            this.flashcards = bool4;
            this.artifactCount = num2;
            this.identifier = str6;
        }
    }

    public NotesEventLog(@NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NotesEventLog) && Intrinsics.b(this.payload, ((NotesEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "NotesEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
