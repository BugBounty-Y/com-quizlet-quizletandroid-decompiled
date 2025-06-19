package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.c1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4472c1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4472c1[] $VALUES;

    @NotNull
    public static final C4469b1 Companion;
    public static final EnumC4472c1 EDGY_DATA_PROMPT;
    public static final EnumC4472c1 INSTRUCTIONS;
    public static final EnumC4472c1 RECENT_SEARCHES;
    public static final EnumC4472c1 RECOMMENDATIONS;

    @NotNull
    private final String value;

    static {
        EnumC4472c1 enumC4472c1 = new EnumC4472c1("EDGY_DATA_PROMPT", 0, "edgy_data_prompt");
        EDGY_DATA_PROMPT = enumC4472c1;
        EnumC4472c1 enumC4472c12 = new EnumC4472c1("INSTRUCTIONS", 1, "instructions");
        INSTRUCTIONS = enumC4472c12;
        EnumC4472c1 enumC4472c13 = new EnumC4472c1("RECENT_SEARCHES", 2, "recent_searches");
        RECENT_SEARCHES = enumC4472c13;
        EnumC4472c1 enumC4472c14 = new EnumC4472c1("RECOMMENDATIONS", 3, "recommendations");
        RECOMMENDATIONS = enumC4472c14;
        EnumC4472c1[] enumC4472c1Arr = {enumC4472c1, enumC4472c12, enumC4472c13, enumC4472c14};
        $VALUES = enumC4472c1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4472c1Arr);
        Companion = new C4469b1();
    }

    public EnumC4472c1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4472c1 valueOf(String str) {
        return (EnumC4472c1) Enum.valueOf(EnumC4472c1.class, str);
    }

    public static EnumC4472c1[] values() {
        return (EnumC4472c1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
