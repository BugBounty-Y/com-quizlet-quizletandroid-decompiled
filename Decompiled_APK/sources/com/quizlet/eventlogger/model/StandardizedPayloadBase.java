package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Metadata
/* loaded from: classes2.dex */
public abstract class StandardizedPayloadBase {

    @JsonProperty("app_session_id")
    private String appSessionId;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("dedupe_id")
    private String dedupeId;

    @JsonProperty("is_online")
    private Boolean isOnline;

    @JsonProperty("is_wifi")
    private Boolean isWifi;

    @JsonProperty("platform")
    private int platform;

    @JsonProperty("user_id")
    private Long userId;

    public final void a(Long l, UUID clientId, String appSessionId) {
        Intrinsics.checkNotNullParameter(clientId, "clientId");
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        this.userId = l;
        this.clientId = clientId.toString();
        this.appSessionId = appSessionId;
        this.platform = 3;
        this.dedupeId = UUID.randomUUID().toString();
    }

    public final void b(boolean z, boolean z2) {
        this.isOnline = Boolean.valueOf(z);
        this.isWifi = Boolean.valueOf(z2);
    }

    public final String getAppSessionId() {
        return this.appSessionId;
    }

    @JsonIgnore
    public final String getClientId() {
        return this.clientId;
    }

    public final String getDedupeId() {
        return this.dedupeId;
    }

    public final int getPlatform() {
        return this.platform;
    }

    public final Long getUserId() {
        return this.userId;
    }

    public final void setAppSessionId(String str) {
        this.appSessionId = str;
    }

    public final void setClientId(String str) {
        this.clientId = str;
    }

    public final void setDedupeId(String str) {
        this.dedupeId = str;
    }

    public final void setOnline(Boolean bool) {
        this.isOnline = bool;
    }

    public final void setPlatform(int i) {
        this.platform = i;
    }

    public final void setUserId(Long l) {
        this.userId = l;
    }

    public final void setWifi(Boolean bool) {
        this.isWifi = bool;
    }
}
