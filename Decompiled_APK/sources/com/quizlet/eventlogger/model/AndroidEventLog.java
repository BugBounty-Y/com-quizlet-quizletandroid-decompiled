package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AndroidEventLog extends EventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final AndroidEventPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static AndroidEventLog a(int i, long j, long j2, String action, String str) {
            Intrinsics.checkNotNullParameter(action, "action");
            long j3 = EventLogBuilder.b;
            int i2 = EventLogBuilder.c;
            EventLogBuilder.c = i2 + 1;
            String str2 = null;
            String str3 = null;
            Boolean bool = null;
            AndroidEventLog androidEventLog = new AndroidEventLog(new AndroidEventPayload(str2, str, str3, null, bool, null, null, null, null, null, null, Long.valueOf(j3), Integer.valueOf(i2), null, null, null, null, null, null, Integer.valueOf(i), Long.valueOf(j2), Long.valueOf(j), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, -3676203, 536870911, null));
            androidEventLog.setAction(action);
            return androidEventLog;
        }

        public static AndroidEventLog b(Companion companion, String action, String str, int i) {
            String str2 = (i & 2) != 0 ? null : str;
            companion.getClass();
            Intrinsics.checkNotNullParameter(action, "action");
            long j = EventLogBuilder.b;
            int i2 = EventLogBuilder.c;
            EventLogBuilder.c = i2 + 1;
            String str3 = null;
            String str4 = null;
            AndroidEventLog androidEventLog = new AndroidEventLog(new AndroidEventPayload(str3, str2, str4, null, null, null, null, null, null, null, null, Long.valueOf(j), Integer.valueOf(i2), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, -6187, 536870911, null));
            androidEventLog.setAction(action);
            return androidEventLog;
        }

        private Companion() {
        }
    }

    public AndroidEventLog(@NotNull AndroidEventPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        payload.setDedupeId(UUID.randomUUID().toString());
    }

    public static final AndroidEventLog c(String action) {
        Companion companion = b;
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        return Companion.b(companion, action, null, 14);
    }

    public static final AndroidEventLog d(String action, String str) {
        Companion companion = b;
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        return Companion.b(companion, action, str, 12);
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        setAppSessionId(appSessionId.toString());
        this.payload.setDeviceId(androidDeviceId.toString());
        setHasLoggedInBefore(bool);
        if (currentUserEvent == null || !currentUserEvent.c) {
            setUserId(null);
            setUsername(null);
        } else {
            setUserId(Long.valueOf(currentUserEvent.getCurrentUser().getId()));
            setUsername(currentUserEvent.getCurrentUser().getUsername());
        }
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void b(boolean z, boolean z2) {
        this.payload.setOnline(Boolean.valueOf(z));
        this.payload.setWifi(Boolean.valueOf(z2));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof AndroidEventLog) && Intrinsics.b(this.payload, ((AndroidEventLog) obj).payload);
    }

    @JsonIgnore
    public final String getAppSessionId() {
        return this.payload.getAppSessionId();
    }

    @JsonIgnore
    public final String getAuthenticationProvider() {
        return this.payload.getAuthenticationProvider();
    }

    @JsonIgnore
    public final String getCardStyle() {
        return this.payload.getCardStyle();
    }

    @JsonIgnore
    public final Long getClassId() {
        return this.payload.getClassId();
    }

    @JsonIgnore
    public final String getDedupeId() {
        return this.payload.getDedupeId();
    }

    @JsonIgnore
    public final Integer getDepth() {
        return this.payload.getDepth();
    }

    @JsonIgnore
    public final String getDeviceId() {
        return this.payload.getDeviceId();
    }

    @JsonIgnore
    public final String getFlashcardMode() {
        return this.payload.getFlashcardMode();
    }

    @JsonIgnore
    public final Integer getFlashcardsNumRoundsCompleted() {
        return this.payload.getFlashcardsNumRoundsCompleted();
    }

    @JsonIgnore
    public final Integer getFlashcardsPctSwipedOutOfStack() {
        return this.payload.getFlashcardsPctSwipedOutOfStack();
    }

    @JsonIgnore
    public final Long getFolderId() {
        return this.payload.getFolderId();
    }

    @JsonIgnore
    public final Integer getGmsVersion() {
        return this.payload.getGmsVersion();
    }

    @JsonIgnore
    public final Boolean getHasLoggedInBefore() {
        return this.payload.getHasLoggedInBefore();
    }

    @JsonIgnore
    public final Boolean getLandscape() {
        return this.payload.a();
    }

    @JsonIgnore
    public final String getLocation() {
        return this.payload.getLocation();
    }

    @JsonIgnore
    public final String getMessage() {
        return this.payload.getMessage();
    }

    @NotNull
    public final AndroidEventPayload getPayload() {
        return this.payload;
    }

    @JsonIgnore
    public final String getPreviousScreenName() {
        return this.payload.getPreviousScreenName();
    }

    @JsonIgnore
    public final String getPromptSide() {
        return this.payload.getPromptSide();
    }

    @JsonIgnore
    public final String getScreenName() {
        return this.payload.getScreenName();
    }

    @JsonIgnore
    public final Long getSetId() {
        return this.payload.getSetId();
    }

    @JsonIgnore
    public final Boolean getSignUp() {
        return this.payload.b();
    }

    @JsonIgnore
    public final Integer getSize() {
        return this.payload.getSize();
    }

    @JsonIgnore
    public final String getSorting() {
        return this.payload.getSorting();
    }

    @JsonIgnore
    public final String getUserAction() {
        return this.payload.getUserAction();
    }

    @JsonIgnore
    public final String getUserActionFlashcards() {
        return this.payload.getUserAction();
    }

    @JsonIgnore
    public final Long getUserId() {
        return this.payload.getUserId();
    }

    @JsonIgnore
    public final String getUsername() {
        return this.payload.getUsername();
    }

    @JsonIgnore
    public final Long getVisitDurationMs() {
        return this.payload.getVisitDurationMs();
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final void setAppSessionId(String str) {
        this.payload.setAppSessionId(str);
    }

    public final void setAuthenticationProvider(String str) {
        this.payload.setAuthenticationProvider(str);
    }

    public final void setCardStyle(String str) {
        this.payload.setCardStyle(str);
    }

    public final void setClassId(Long l) {
        this.payload.setClassId(l);
    }

    public final void setDedupeId(String str) {
        this.payload.setDedupeId(str);
    }

    public final void setDepth(Integer num) {
        this.payload.setDepth(num);
    }

    public final void setEnabled(Boolean bool) {
        this.payload.setEnabled(bool);
    }

    public final void setFlashcardMode(String str) {
        this.payload.setFlashcardMode(str);
    }

    public final void setFlashcardsNumRoundsCompleted(Integer num) {
        this.payload.setFlashcardsNumRoundsCompleted(num);
    }

    public final void setFlashcardsPctSwipedOutOfStack(Integer num) {
        this.payload.setFlashcardsPctSwipedOutOfStack(num);
    }

    public final void setFolderId(Long l) {
        this.payload.setFolderId(l);
    }

    public final void setGmsVersion(Integer num) {
        this.payload.setGmsVersion(num);
    }

    public final void setHasLoggedInBefore(Boolean bool) {
        this.payload.setHasLoggedInBefore(bool);
    }

    public final void setLandscape(Boolean bool) {
        this.payload.setLandscape(bool);
    }

    public final void setLocation(String str) {
        this.payload.setLocation(str);
    }

    public final void setMessage(String str) {
        this.payload.setMessage(str);
    }

    public final void setPreviousScreenName(String str) {
        this.payload.setPreviousScreenName(str);
    }

    public final void setPromptSide(String str) {
        this.payload.setPromptSide(str);
    }

    public final void setSetId(Long l) {
        this.payload.setSetId(l);
    }

    public final void setSignUp(Boolean bool) {
        this.payload.setSignUp(bool);
    }

    public final void setSize(Integer num) {
        this.payload.setSize(num);
    }

    public final void setSorting(String str) {
        this.payload.setSorting(str);
    }

    public final void setUserAction(String str) {
        this.payload.setUserAction(str);
    }

    public final void setUserActionFlashcards(String str) {
        this.payload.setUserAction(str);
    }

    public final void setUserId(Long l) {
        this.payload.setUserId(l);
    }

    public final void setUsername(String str) {
        this.payload.setUsername(str);
    }

    public final void setVisitDurationMs(Long l) {
        this.payload.setVisitDurationMs(l);
    }

    public final void setWhatsAppShareDisplayed(Boolean bool) {
        this.payload.setWhatsAppShareDisplayed(bool);
    }

    public final String toString() {
        return "AndroidEventLog(payload=" + this.payload + ")";
    }
}
