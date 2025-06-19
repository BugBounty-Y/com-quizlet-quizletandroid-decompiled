package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.o0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4507o0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4507o0[] $VALUES;

    @NotNull
    public static final C4504n0 Companion;
    public static final EnumC4507o0 MATH;
    public static final EnumC4507o0 PLAINTEXT;

    @NotNull
    private final String value;

    static {
        EnumC4507o0 enumC4507o0 = new EnumC4507o0("MATH", 0, "math");
        MATH = enumC4507o0;
        EnumC4507o0 enumC4507o02 = new EnumC4507o0("PLAINTEXT", 1, "plaintext");
        PLAINTEXT = enumC4507o02;
        EnumC4507o0[] enumC4507o0Arr = {enumC4507o0, enumC4507o02};
        $VALUES = enumC4507o0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4507o0Arr);
        Companion = new C4504n0();
    }

    public EnumC4507o0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4507o0 valueOf(String str) {
        return (EnumC4507o0) Enum.valueOf(EnumC4507o0.class, str);
    }

    public static EnumC4507o0[] values() {
        return (EnumC4507o0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
