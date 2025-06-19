package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class DismissType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ DismissType[] $VALUES;
    public static final DismissType AUTO_DISMISS = new DismissType("AUTO_DISMISS", 0);
    public static final DismissType SWIPE = new DismissType("SWIPE", 1);
    public static final DismissType MANUAL = new DismissType("MANUAL", 2);

    private static final /* synthetic */ DismissType[] $values() {
        return new DismissType[]{AUTO_DISMISS, SWIPE, MANUAL};
    }

    static {
        DismissType[] dismissTypeArr$values = $values();
        $VALUES = dismissTypeArr$values;
        $ENTRIES = AbstractC3328d.f(dismissTypeArr$values);
    }

    private DismissType(String str, int i) {
    }

    public static DismissType valueOf(String str) {
        return (DismissType) Enum.valueOf(DismissType.class, str);
    }

    public static DismissType[] values() {
        return (DismissType[]) $VALUES.clone();
    }
}
