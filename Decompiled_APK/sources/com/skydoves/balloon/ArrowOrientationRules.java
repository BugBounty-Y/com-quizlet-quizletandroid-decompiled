package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class ArrowOrientationRules {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ ArrowOrientationRules[] $VALUES;
    public static final ArrowOrientationRules ALIGN_ANCHOR = new ArrowOrientationRules("ALIGN_ANCHOR", 0);
    public static final ArrowOrientationRules ALIGN_FIXED = new ArrowOrientationRules("ALIGN_FIXED", 1);

    private static final /* synthetic */ ArrowOrientationRules[] $values() {
        return new ArrowOrientationRules[]{ALIGN_ANCHOR, ALIGN_FIXED};
    }

    static {
        ArrowOrientationRules[] arrowOrientationRulesArr$values = $values();
        $VALUES = arrowOrientationRulesArr$values;
        $ENTRIES = AbstractC3328d.f(arrowOrientationRulesArr$values);
    }

    private ArrowOrientationRules(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static ArrowOrientationRules valueOf(String str) {
        return (ArrowOrientationRules) Enum.valueOf(ArrowOrientationRules.class, str);
    }

    public static ArrowOrientationRules[] values() {
        return (ArrowOrientationRules[]) $VALUES.clone();
    }
}
