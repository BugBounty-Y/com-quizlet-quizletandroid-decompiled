package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Metadata
/* loaded from: classes2.dex */
public final class EmailTrackingPayload {

    @JsonProperty("app_session_id")
    private String appSessionId;

    @JsonProperty("mailgun_client_os")
    private String clientOs;

    @JsonProperty("dedupe_id")
    private String dedupeId;

    @JsonProperty("mailgun_device_type")
    private String deviceType;

    @JsonProperty("email_address")
    private String emailAddress;

    @JsonProperty("mailgun_tag")
    private String mailgunTag;

    @JsonProperty("name")
    private String name;

    @JsonProperty("page")
    private String page;

    @JsonProperty("source_key")
    private Long sourceKey;

    @JsonProperty("source_type")
    private String sourceType;

    @JsonProperty("uid")
    private Long uid;

    @JsonProperty("username")
    private String username;

    public final String getAppSessionId() {
        return this.appSessionId;
    }

    public final String getClientOs() {
        return this.clientOs;
    }

    public final String getDedupeId() {
        return this.dedupeId;
    }

    public final String getDeviceType() {
        return this.deviceType;
    }

    public final String getEmailAddress() {
        return this.emailAddress;
    }

    public final String getMailgunTag() {
        return this.mailgunTag;
    }

    public final String getName() {
        return this.name;
    }

    public final String getPage() {
        return this.page;
    }

    public final Long getSourceKey() {
        return this.sourceKey;
    }

    public final String getSourceType() {
        return this.sourceType;
    }

    public final Long getUid() {
        return this.uid;
    }

    public final String getUsername() {
        return this.username;
    }

    public final void setAppSessionId(String str) {
        this.appSessionId = str;
    }

    public final void setClientOs(String str) {
        this.clientOs = str;
    }

    @JsonIgnore
    public final void setDedupeId(String str) {
        this.dedupeId = str;
    }

    public final void setDeviceType(String str) {
        this.deviceType = str;
    }

    public final void setEmailAddress(String str) {
        this.emailAddress = str;
    }

    public final void setMailgunTag(String str) {
        this.mailgunTag = str;
    }

    public final void setName(String str) {
        this.name = str;
    }

    public final void setPage(String str) {
        this.page = str;
    }

    public final void setSourceKey(Long l) {
        this.sourceKey = l;
    }

    public final void setSourceType(String str) {
        this.sourceType = str;
    }

    public final void setUid(Long l) {
        this.uid = l;
    }

    public final void setUsername(String str) {
        this.username = str;
    }
}
