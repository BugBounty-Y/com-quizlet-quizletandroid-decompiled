package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class BrazePushEventType {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BrazePushEventType[] $VALUES;
    public static final BrazePushEventType NOTIFICATION_RECEIVED = new BrazePushEventType("NOTIFICATION_RECEIVED", 0);
    public static final BrazePushEventType NOTIFICATION_DELETED = new BrazePushEventType("NOTIFICATION_DELETED", 1);
    public static final BrazePushEventType NOTIFICATION_OPENED = new BrazePushEventType("NOTIFICATION_OPENED", 2);

    private static final /* synthetic */ BrazePushEventType[] $values() {
        return new BrazePushEventType[]{NOTIFICATION_RECEIVED, NOTIFICATION_DELETED, NOTIFICATION_OPENED};
    }

    static {
        BrazePushEventType[] brazePushEventTypeArr$values = $values();
        $VALUES = brazePushEventTypeArr$values;
        $ENTRIES = AbstractC3328d.f(brazePushEventTypeArr$values);
    }

    private BrazePushEventType(String str, int i) {
    }

    public static BrazePushEventType valueOf(String str) {
        return (BrazePushEventType) Enum.valueOf(BrazePushEventType.class, str);
    }

    public static BrazePushEventType[] values() {
        return (BrazePushEventType[]) $VALUES.clone();
    }
}
