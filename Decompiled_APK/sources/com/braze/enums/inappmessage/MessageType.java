package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class MessageType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ MessageType[] $VALUES;
    public static final MessageType SLIDEUP = new MessageType("SLIDEUP", 0);
    public static final MessageType MODAL = new MessageType("MODAL", 1);
    public static final MessageType FULL = new MessageType("FULL", 2);
    public static final MessageType HTML_FULL = new MessageType("HTML_FULL", 3);
    public static final MessageType HTML = new MessageType("HTML", 4);
    public static final MessageType CONTROL = new MessageType("CONTROL", 5);

    private static final /* synthetic */ MessageType[] $values() {
        return new MessageType[]{SLIDEUP, MODAL, FULL, HTML_FULL, HTML, CONTROL};
    }

    static {
        MessageType[] messageTypeArr$values = $values();
        $VALUES = messageTypeArr$values;
        $ENTRIES = AbstractC3328d.f(messageTypeArr$values);
    }

    private MessageType(String str, int i) {
    }

    public static MessageType valueOf(String str) {
        return (MessageType) Enum.valueOf(MessageType.class, str);
    }

    public static MessageType[] values() {
        return (MessageType[]) $VALUES.clone();
    }
}
