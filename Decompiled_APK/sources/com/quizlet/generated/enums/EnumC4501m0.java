package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.m0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4501m0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4501m0[] $VALUES;
    public static final EnumC4501m0 CORRECT;

    @NotNull
    public static final C4498l0 Companion;
    public static final EnumC4501m0 INCORRECT;
    public static final EnumC4501m0 OVERRIDDEN_CORRECT;
    public static final EnumC4501m0 SKIPPED;
    private final int value;

    static {
        EnumC4501m0 enumC4501m0 = new EnumC4501m0("CORRECT", 0, 0);
        CORRECT = enumC4501m0;
        EnumC4501m0 enumC4501m02 = new EnumC4501m0("INCORRECT", 1, 1);
        INCORRECT = enumC4501m02;
        EnumC4501m0 enumC4501m03 = new EnumC4501m0("SKIPPED", 2, 2);
        SKIPPED = enumC4501m03;
        EnumC4501m0 enumC4501m04 = new EnumC4501m0("OVERRIDDEN_CORRECT", 3, 3);
        OVERRIDDEN_CORRECT = enumC4501m04;
        EnumC4501m0[] enumC4501m0Arr = {enumC4501m0, enumC4501m02, enumC4501m03, enumC4501m04};
        $VALUES = enumC4501m0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4501m0Arr);
        Companion = new C4498l0();
    }

    public EnumC4501m0(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4501m0 valueOf(String str) {
        return (EnumC4501m0) Enum.valueOf(EnumC4501m0.class, str);
    }

    public static EnumC4501m0[] values() {
        return (EnumC4501m0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
