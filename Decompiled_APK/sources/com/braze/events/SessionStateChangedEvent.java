package com.braze.events;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class SessionStateChangedEvent {
    private final ChangeType eventType;
    private final String sessionId;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class ChangeType {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ ChangeType[] $VALUES;
        public static final ChangeType SESSION_STARTED = new ChangeType("SESSION_STARTED", 0);
        public static final ChangeType SESSION_ENDED = new ChangeType("SESSION_ENDED", 1);

        private static final /* synthetic */ ChangeType[] $values() {
            return new ChangeType[]{SESSION_STARTED, SESSION_ENDED};
        }

        static {
            ChangeType[] changeTypeArr$values = $values();
            $VALUES = changeTypeArr$values;
            $ENTRIES = AbstractC3328d.f(changeTypeArr$values);
        }

        private ChangeType(String str, int i) {
        }

        public static ChangeType valueOf(String str) {
            return (ChangeType) Enum.valueOf(ChangeType.class, str);
        }

        public static ChangeType[] values() {
            return (ChangeType[]) $VALUES.clone();
        }
    }

    public SessionStateChangedEvent(String sessionId, ChangeType eventType) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        this.sessionId = sessionId;
        this.eventType = eventType;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SessionStateChangedEvent)) {
            return false;
        }
        SessionStateChangedEvent sessionStateChangedEvent = (SessionStateChangedEvent) obj;
        return Intrinsics.b(this.sessionId, sessionStateChangedEvent.sessionId) && this.eventType == sessionStateChangedEvent.eventType;
    }

    public int hashCode() {
        return this.eventType.hashCode() + (this.sessionId.hashCode() * 31);
    }

    public String toString() {
        return "SessionStateChangedEvent{sessionId='" + this.sessionId + "', eventType='" + this.eventType + "'}'";
    }
}
