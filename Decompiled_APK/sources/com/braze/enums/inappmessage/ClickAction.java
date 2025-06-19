package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class ClickAction {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ ClickAction[] $VALUES;
    public static final ClickAction NEWS_FEED = new ClickAction("NEWS_FEED", 0);
    public static final ClickAction URI = new ClickAction("URI", 1);
    public static final ClickAction NONE = new ClickAction("NONE", 2);

    private static final /* synthetic */ ClickAction[] $values() {
        return new ClickAction[]{NEWS_FEED, URI, NONE};
    }

    static {
        ClickAction[] clickActionArr$values = $values();
        $VALUES = clickActionArr$values;
        $ENTRIES = AbstractC3328d.f(clickActionArr$values);
    }

    private ClickAction(String str, int i) {
    }

    public static ClickAction valueOf(String str) {
        return (ClickAction) Enum.valueOf(ClickAction.class, str);
    }

    public static ClickAction[] values() {
        return (ClickAction[]) $VALUES.clone();
    }
}
