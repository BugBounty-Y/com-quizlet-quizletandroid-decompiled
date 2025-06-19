package com.braze.events;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class NoMatchingTriggerEvent {
    private final String sourceEventType;

    public NoMatchingTriggerEvent(String sourceEventType) {
        Intrinsics.checkNotNullParameter(sourceEventType, "sourceEventType");
        this.sourceEventType = sourceEventType;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NoMatchingTriggerEvent) && Intrinsics.b(this.sourceEventType, ((NoMatchingTriggerEvent) obj).sourceEventType);
    }

    public int hashCode() {
        return this.sourceEventType.hashCode();
    }

    public String toString() {
        return d0.r(new StringBuilder("NoMatchingTriggerEvent(sourceEventType="), this.sourceEventType, ')');
    }
}
