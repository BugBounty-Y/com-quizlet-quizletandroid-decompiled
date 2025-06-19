package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class SlideFrom {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ SlideFrom[] $VALUES;
    public static final SlideFrom TOP = new SlideFrom("TOP", 0);
    public static final SlideFrom BOTTOM = new SlideFrom("BOTTOM", 1);

    private static final /* synthetic */ SlideFrom[] $values() {
        return new SlideFrom[]{TOP, BOTTOM};
    }

    static {
        SlideFrom[] slideFromArr$values = $values();
        $VALUES = slideFromArr$values;
        $ENTRIES = AbstractC3328d.f(slideFromArr$values);
    }

    private SlideFrom(String str, int i) {
    }

    public static SlideFrom valueOf(String str) {
        return (SlideFrom) Enum.valueOf(SlideFrom.class, str);
    }

    public static SlideFrom[] values() {
        return (SlideFrom[]) $VALUES.clone();
    }
}
