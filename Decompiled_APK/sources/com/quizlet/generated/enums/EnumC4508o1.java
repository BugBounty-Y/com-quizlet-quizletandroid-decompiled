package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.o1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4508o1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4508o1[] $VALUES;
    public static final EnumC4508o1 CLOSE;
    public static final EnumC4508o1 CORRECT;

    @NotNull
    public static final C4505n1 Companion;
    public static final EnumC4508o1 PARTIAL;
    public static final EnumC4508o1 WRONG;

    @NotNull
    private final String value;

    static {
        EnumC4508o1 enumC4508o1 = new EnumC4508o1("CORRECT", 0, "correct");
        CORRECT = enumC4508o1;
        EnumC4508o1 enumC4508o12 = new EnumC4508o1("CLOSE", 1, "close");
        CLOSE = enumC4508o12;
        EnumC4508o1 enumC4508o13 = new EnumC4508o1("PARTIAL", 2, "partial");
        PARTIAL = enumC4508o13;
        EnumC4508o1 enumC4508o14 = new EnumC4508o1("WRONG", 3, "wrong");
        WRONG = enumC4508o14;
        EnumC4508o1[] enumC4508o1Arr = {enumC4508o1, enumC4508o12, enumC4508o13, enumC4508o14};
        $VALUES = enumC4508o1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4508o1Arr);
        Companion = new C4505n1();
    }

    public EnumC4508o1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4508o1 valueOf(String str) {
        return (EnumC4508o1) Enum.valueOf(EnumC4508o1.class, str);
    }

    public static EnumC4508o1[] values() {
        return (EnumC4508o1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
