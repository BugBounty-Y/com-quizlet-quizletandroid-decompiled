package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.q1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4514q1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4514q1[] $VALUES;

    @NotNull
    public static final C4511p1 Companion;
    public static final EnumC4514q1 MULTIPLE_CHOICE_QUESTION;
    public static final EnumC4514q1 N_SIDED_CARD;
    private final int value;

    static {
        EnumC4514q1 enumC4514q1 = new EnumC4514q1("MULTIPLE_CHOICE_QUESTION", 0, 1);
        MULTIPLE_CHOICE_QUESTION = enumC4514q1;
        EnumC4514q1 enumC4514q12 = new EnumC4514q1("N_SIDED_CARD", 1, 2);
        N_SIDED_CARD = enumC4514q12;
        EnumC4514q1[] enumC4514q1Arr = {enumC4514q1, enumC4514q12};
        $VALUES = enumC4514q1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4514q1Arr);
        Companion = new C4511p1();
    }

    public EnumC4514q1(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4514q1 valueOf(String str) {
        return (EnumC4514q1) Enum.valueOf(EnumC4514q1.class, str);
    }

    public static EnumC4514q1[] values() {
        return (EnumC4514q1[]) $VALUES.clone();
    }
}
