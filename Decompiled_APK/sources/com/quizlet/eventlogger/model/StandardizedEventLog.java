package com.quizlet.eventlogger.model;

import com.quizlet.eventlogger.events.CurrentUserEvent;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class StandardizedEventLog extends EventLog {
    @Override // com.quizlet.eventlogger.model.EventLog
    public void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        StandardizedPayloadBase payload = getPayload();
        if (payload != null) {
            Long lValueOf = (currentUserEvent == null || !currentUserEvent.c) ? null : Long.valueOf(currentUserEvent.getCurrentUser().getId());
            String string = appSessionId.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            payload.a(lValueOf, androidDeviceId, string);
        }
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void b(boolean z, boolean z2) {
        StandardizedPayloadBase payload = getPayload();
        if (payload != null) {
            payload.b(z, z2);
        }
    }

    public abstract StandardizedPayloadBase getPayload();
}
