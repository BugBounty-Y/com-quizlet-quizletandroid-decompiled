package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class Channel {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Channel[] $VALUES;
    public static final Channel PUSH = new Channel("PUSH", 0);
    public static final Channel INAPP_MESSAGE = new Channel("INAPP_MESSAGE", 1);
    public static final Channel NEWS_FEED = new Channel("NEWS_FEED", 2);
    public static final Channel CONTENT_CARD = new Channel("CONTENT_CARD", 3);
    public static final Channel UNKNOWN = new Channel("UNKNOWN", 4);
    public static final Channel BANNER = new Channel("BANNER", 5);

    private static final /* synthetic */ Channel[] $values() {
        return new Channel[]{PUSH, INAPP_MESSAGE, NEWS_FEED, CONTENT_CARD, UNKNOWN, BANNER};
    }

    static {
        Channel[] channelArr$values = $values();
        $VALUES = channelArr$values;
        $ENTRIES = AbstractC3328d.f(channelArr$values);
    }

    private Channel(String str, int i) {
    }

    public static Channel valueOf(String str) {
        return (Channel) Enum.valueOf(Channel.class, str);
    }

    public static Channel[] values() {
        return (Channel[]) $VALUES.clone();
    }
}
