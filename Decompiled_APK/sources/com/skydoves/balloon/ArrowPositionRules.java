package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class ArrowPositionRules {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ ArrowPositionRules[] $VALUES;
    public static final ArrowPositionRules ALIGN_BALLOON = new ArrowPositionRules("ALIGN_BALLOON", 0);
    public static final ArrowPositionRules ALIGN_ANCHOR = new ArrowPositionRules("ALIGN_ANCHOR", 1);

    private static final /* synthetic */ ArrowPositionRules[] $values() {
        return new ArrowPositionRules[]{ALIGN_BALLOON, ALIGN_ANCHOR};
    }

    static {
        ArrowPositionRules[] arrowPositionRulesArr$values = $values();
        $VALUES = arrowPositionRulesArr$values;
        $ENTRIES = AbstractC3328d.f(arrowPositionRulesArr$values);
    }

    private ArrowPositionRules(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static ArrowPositionRules valueOf(String str) {
        return (ArrowPositionRules) Enum.valueOf(ArrowPositionRules.class, str);
    }

    public static ArrowPositionRules[] values() {
        return (ArrowPositionRules[]) $VALUES.clone();
    }
}
