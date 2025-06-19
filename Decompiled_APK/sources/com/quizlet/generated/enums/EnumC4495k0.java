package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.k0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4495k0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4495k0[] $VALUES;
    public static final EnumC4495k0 CREATE_SET;

    @NotNull
    public static final C4492j0 Companion;
    public static final EnumC4495k0 HOME;
    private final int value;

    static {
        EnumC4495k0 enumC4495k0 = new EnumC4495k0("HOME", 0, 0);
        HOME = enumC4495k0;
        EnumC4495k0 enumC4495k02 = new EnumC4495k0("CREATE_SET", 1, 1);
        CREATE_SET = enumC4495k02;
        EnumC4495k0[] enumC4495k0Arr = {enumC4495k0, enumC4495k02};
        $VALUES = enumC4495k0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4495k0Arr);
        Companion = new C4492j0();
    }

    public EnumC4495k0(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4495k0 valueOf(String str) {
        return (EnumC4495k0) Enum.valueOf(EnumC4495k0.class, str);
    }

    public static EnumC4495k0[] values() {
        return (EnumC4495k0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
