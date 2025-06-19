package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AudioPlaybackCountsLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final AudioPlayBackCountsPayload payload = new AudioPlayBackCountsPayload();

    @Metadata
    public static final class AudioPlayBackCountsPayload extends StandardizedPayloadBase {

        @JsonProperty("custom_audio_count")
        private Integer customAudioCount;

        @JsonProperty("errors")
        private String errors;

        @JsonProperty("language")
        private String language;

        @JsonProperty("playback_action")
        private String playbackAction;

        @JsonProperty("server_set_id")
        private Long serverSetId;

        @JsonProperty("study_mode")
        private Integer studyMode;

        @JsonProperty("study_session_id")
        private String studySessionId;

        @JsonProperty("tts_count")
        private Integer ttsCount;

        public final Integer getCustomAudioCount() {
            return this.customAudioCount;
        }

        public final String getErrors() {
            return this.errors;
        }

        public final String getLanguage() {
            return this.language;
        }

        public final String getPlaybackAction() {
            return this.playbackAction;
        }

        public final Long getServerSetId() {
            return this.serverSetId;
        }

        public final Integer getStudyMode() {
            return this.studyMode;
        }

        public final String getStudySessionId() {
            return this.studySessionId;
        }

        public final Integer getTtsCount() {
            return this.ttsCount;
        }

        public final void setCustomAudioCount(Integer num) {
            this.customAudioCount = num;
        }

        public final void setErrors(String str) {
            this.errors = str;
        }

        public final void setLanguage(String str) {
            this.language = str;
        }

        public final void setPlaybackAction(String str) {
            this.playbackAction = str;
        }

        public final void setServerSetId(Long l) {
            this.serverSetId = l;
        }

        public final void setStudyMode(Integer num) {
            this.studyMode = num;
        }

        public final void setStudySessionId(String str) {
            this.studySessionId = str;
        }

        public final void setTtsCount(Integer num) {
            this.ttsCount = num;
        }
    }

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static AudioPlaybackCountsLog a(long j, String language) {
            Intrinsics.checkNotNullParameter(language, "language");
            Intrinsics.checkNotNullParameter("audio_button", "action");
            Intrinsics.checkNotNullParameter(language, "language");
            AudioPlaybackCountsLog audioPlaybackCountsLog = new AudioPlaybackCountsLog();
            audioPlaybackCountsLog.setAction("audio_button");
            audioPlaybackCountsLog.getPayload().setPlaybackAction("audio_button");
            audioPlaybackCountsLog.getPayload().setLanguage(language);
            audioPlaybackCountsLog.getPayload().setServerSetId(Long.valueOf(j));
            return audioPlaybackCountsLog;
        }

        private Companion() {
        }
    }

    public AudioPlaybackCountsLog() {
        setTable(EnumC4503n.AUDIO_PLAYBACK_COUNTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public AudioPlayBackCountsPayload getPayload() {
        return this.payload;
    }
}
