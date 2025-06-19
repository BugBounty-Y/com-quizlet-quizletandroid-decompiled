package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ScanNotesPaywallEventLog extends StandardizedEventLog {

    @JsonProperty("payload")
    @NotNull
    private final Payload payload;

    @JsonProperty("source")
    private String source;

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {
    }

    public /* synthetic */ ScanNotesPaywallEventLog(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, str2);
    }

    public final String getSource() {
        return this.source;
    }

    public final void setSource(String str) {
        this.source = str;
    }

    public ScanNotesPaywallEventLog(String str, @NotNull String action) {
        Intrinsics.checkNotNullParameter(action, "action");
        this.source = str;
        this.payload = new Payload();
        setTable(EnumC4503n.ANDROID_EVENTS);
        setAction(action);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
