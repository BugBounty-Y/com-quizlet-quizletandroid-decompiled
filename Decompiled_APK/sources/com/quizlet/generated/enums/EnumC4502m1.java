package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.m1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4502m1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4502m1[] $VALUES;

    @NotNull
    public static final C4499l1 Companion;
    public static final EnumC4502m1 ITEM_TO_ITEM;
    public static final EnumC4502m1 MERGED_USER_BASED_AND_ITEM_TO_ITEM;
    public static final EnumC4502m1 USER_TO_USER;
    private final int value;

    static {
        EnumC4502m1 enumC4502m1 = new EnumC4502m1("MERGED_USER_BASED_AND_ITEM_TO_ITEM", 0, 1);
        MERGED_USER_BASED_AND_ITEM_TO_ITEM = enumC4502m1;
        EnumC4502m1 enumC4502m12 = new EnumC4502m1("USER_TO_USER", 1, 2);
        USER_TO_USER = enumC4502m12;
        EnumC4502m1 enumC4502m13 = new EnumC4502m1("ITEM_TO_ITEM", 2, 3);
        ITEM_TO_ITEM = enumC4502m13;
        EnumC4502m1[] enumC4502m1Arr = {enumC4502m1, enumC4502m12, enumC4502m13};
        $VALUES = enumC4502m1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4502m1Arr);
        Companion = new C4499l1();
    }

    public EnumC4502m1(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4502m1 valueOf(String str) {
        return (EnumC4502m1) Enum.valueOf(EnumC4502m1.class, str);
    }

    public static EnumC4502m1[] values() {
        return (EnumC4502m1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
