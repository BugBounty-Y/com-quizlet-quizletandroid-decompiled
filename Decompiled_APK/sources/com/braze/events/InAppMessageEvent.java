package com.braze.events;

import com.braze.models.inappmessage.IInAppMessage;
import com.braze.support.JsonUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageEvent {
    private final IInAppMessage inAppMessage;
    private final com.braze.triggers.actions.a triggerAction;
    private final com.braze.triggers.events.b triggerEvent;
    private final String userId;

    public InAppMessageEvent(com.braze.triggers.events.b triggerEvent, com.braze.triggers.actions.a triggerAction, IInAppMessage inAppMessage, String str) {
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        Intrinsics.checkNotNullParameter(triggerAction, "triggerAction");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        this.triggerEvent = triggerEvent;
        this.triggerAction = triggerAction;
        this.inAppMessage = inAppMessage;
        this.userId = str;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof InAppMessageEvent)) {
            return false;
        }
        InAppMessageEvent inAppMessageEvent = (InAppMessageEvent) obj;
        return Intrinsics.b(this.triggerEvent, inAppMessageEvent.triggerEvent) && Intrinsics.b(this.triggerAction, inAppMessageEvent.triggerAction) && Intrinsics.b(this.inAppMessage, inAppMessageEvent.inAppMessage) && Intrinsics.b(this.userId, inAppMessageEvent.userId);
    }

    public final IInAppMessage getInAppMessage() {
        return this.inAppMessage;
    }

    public final com.braze.triggers.actions.a getTriggerAction() {
        return this.triggerAction;
    }

    public final com.braze.triggers.events.b getTriggerEvent() {
        return this.triggerEvent;
    }

    public final String getUserId() {
        return this.userId;
    }

    public int hashCode() {
        int iHashCode = (this.inAppMessage.hashCode() + ((this.triggerAction.hashCode() + (this.triggerEvent.hashCode() * 31)) * 31)) * 31;
        String str = this.userId;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public String toString() {
        return JsonUtils.getPrettyPrintedString(this.inAppMessage.forJsonPut());
    }
}
