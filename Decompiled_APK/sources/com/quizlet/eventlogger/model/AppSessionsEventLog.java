package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AppSessionsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final Payload payload = new Payload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("app_build_number")
        private String appBuildNumber;

        @JsonProperty("app_version")
        private String appVersion;

        @JsonProperty("device_model_name")
        private String deviceModelName;

        @JsonProperty("os_name")
        private String osName;

        @JsonProperty("os_version")
        private String osVersion;

        @JsonProperty("screen_height")
        private int screenHeight;

        @JsonProperty("screen_width")
        private int screenWidth;

        @JsonProperty("screen_x_dpi")
        private int screenXDpi;

        @JsonProperty("screen_y_dpi")
        private int screenYDpi;

        @JsonProperty("session_rank")
        private int sessionRank;

        public final String getAppBuildNumber() {
            return this.appBuildNumber;
        }

        public final String getAppVersion() {
            return this.appVersion;
        }

        public final String getDeviceModelName() {
            return this.deviceModelName;
        }

        public final String getOsName() {
            return this.osName;
        }

        public final String getOsVersion() {
            return this.osVersion;
        }

        public final int getScreenHeight() {
            return this.screenHeight;
        }

        public final int getScreenWidth() {
            return this.screenWidth;
        }

        public final int getScreenXDpi() {
            return this.screenXDpi;
        }

        public final int getScreenYDpi() {
            return this.screenYDpi;
        }

        public final int getSessionRank() {
            return this.sessionRank;
        }

        public final void setAppBuildNumber(String str) {
            this.appBuildNumber = str;
        }

        public final void setAppVersion(String str) {
            this.appVersion = str;
        }

        public final void setDeviceModelName(String str) {
            this.deviceModelName = str;
        }

        public final void setOsName(String str) {
            this.osName = str;
        }

        public final void setOsVersion(String str) {
            this.osVersion = str;
        }

        public final void setScreenHeight(int i) {
            this.screenHeight = i;
        }

        public final void setScreenWidth(int i) {
            this.screenWidth = i;
        }

        public final void setScreenXDpi(int i) {
            this.screenXDpi = i;
        }

        public final void setScreenYDpi(int i) {
            this.screenYDpi = i;
        }

        public final void setSessionRank(int i) {
            this.sessionRank = i;
        }
    }

    public AppSessionsEventLog() {
        setTable(EnumC4503n.APP_SESSIONS);
        setAction("app_launch");
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
