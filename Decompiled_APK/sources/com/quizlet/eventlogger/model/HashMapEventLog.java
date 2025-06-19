package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class HashMapEventLog extends EventLog {

    @JsonProperty("payload")
    @NotNull
    private Map<String, Object> rawPayload = new HashMap();

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        if (currentUserEvent != null && currentUserEvent.c) {
            this.rawPayload.put("user_id", Long.valueOf(currentUserEvent.getCurrentUser().getId()));
        }
        this.rawPayload.put("client_id", androidDeviceId.toString());
        this.rawPayload.put("app_session_id", appSessionId.toString());
        this.rawPayload.put("platform", 3);
        this.rawPayload.put("dedupe_id", UUID.randomUUID().toString());
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void b(boolean z, boolean z2) {
        this.rawPayload.put("is_online", Boolean.valueOf(z));
        this.rawPayload.put("is_wifi", Boolean.valueOf(z2));
    }

    @JsonIgnore
    @NotNull
    public final Map<String, Object> getRawPayload() {
        return this.rawPayload;
    }

    public final void setRawPayload(@NotNull Map<String, Object> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.rawPayload = map;
    }
}
