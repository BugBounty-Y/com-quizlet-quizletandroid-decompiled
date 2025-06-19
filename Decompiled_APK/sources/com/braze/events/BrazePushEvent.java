package com.braze.events;

import com.braze.enums.BrazePushEventType;
import com.braze.models.push.BrazeNotificationPayload;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BrazePushEvent {
    private final BrazePushEventType eventType;
    private final BrazeNotificationPayload notificationPayload;

    public BrazePushEvent(BrazePushEventType eventType, BrazeNotificationPayload notificationPayload) {
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(notificationPayload, "notificationPayload");
        this.eventType = eventType;
        this.notificationPayload = notificationPayload;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BrazePushEvent)) {
            return false;
        }
        BrazePushEvent brazePushEvent = (BrazePushEvent) obj;
        return this.eventType == brazePushEvent.eventType && Intrinsics.b(this.notificationPayload, brazePushEvent.notificationPayload);
    }

    public int hashCode() {
        return this.notificationPayload.hashCode() + (this.eventType.hashCode() * 31);
    }

    public String toString() {
        return "BrazePushEvent(eventType=" + this.eventType + ", notificationPayload=" + this.notificationPayload + ')';
    }
}
