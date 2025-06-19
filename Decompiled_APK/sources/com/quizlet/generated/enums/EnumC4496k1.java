package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.k1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4496k1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4496k1[] $VALUES;
    public static final EnumC4496k1 COURSE_LEARNING_TO_RANK;

    @NotNull
    public static final C4493j1 Companion;
    public static final EnumC4496k1 IMPLICIT_COURSE;
    public static final EnumC4496k1 ITEM_TO_ITEM;
    public static final EnumC4496k1 MERGED_USER_BASED_AND_ITEM_TO_ITEM;
    public static final EnumC4496k1 PREP_PACK_INJECTION_TEST;
    public static final EnumC4496k1 SCHOOL_AND_COURSE_LEARNING_TO_RANK;
    public static final EnumC4496k1 SCHOOL_AND_COURSE_PERSONALIZED;
    public static final EnumC4496k1 SCHOOL_LEARNING_TO_RANK;
    public static final EnumC4496k1 USER_TO_USER;
    private final int value;

    static {
        EnumC4496k1 enumC4496k1 = new EnumC4496k1("MERGED_USER_BASED_AND_ITEM_TO_ITEM", 0, 1);
        MERGED_USER_BASED_AND_ITEM_TO_ITEM = enumC4496k1;
        EnumC4496k1 enumC4496k12 = new EnumC4496k1("USER_TO_USER", 1, 2);
        USER_TO_USER = enumC4496k12;
        EnumC4496k1 enumC4496k13 = new EnumC4496k1("ITEM_TO_ITEM", 2, 3);
        ITEM_TO_ITEM = enumC4496k13;
        EnumC4496k1 enumC4496k14 = new EnumC4496k1("SCHOOL_AND_COURSE_LEARNING_TO_RANK", 3, 4);
        SCHOOL_AND_COURSE_LEARNING_TO_RANK = enumC4496k14;
        EnumC4496k1 enumC4496k15 = new EnumC4496k1("COURSE_LEARNING_TO_RANK", 4, 5);
        COURSE_LEARNING_TO_RANK = enumC4496k15;
        EnumC4496k1 enumC4496k16 = new EnumC4496k1("SCHOOL_LEARNING_TO_RANK", 5, 6);
        SCHOOL_LEARNING_TO_RANK = enumC4496k16;
        EnumC4496k1 enumC4496k17 = new EnumC4496k1("SCHOOL_AND_COURSE_PERSONALIZED", 6, 7);
        SCHOOL_AND_COURSE_PERSONALIZED = enumC4496k17;
        EnumC4496k1 enumC4496k18 = new EnumC4496k1("PREP_PACK_INJECTION_TEST", 7, 8);
        PREP_PACK_INJECTION_TEST = enumC4496k18;
        EnumC4496k1 enumC4496k19 = new EnumC4496k1("IMPLICIT_COURSE", 8, 9);
        IMPLICIT_COURSE = enumC4496k19;
        EnumC4496k1[] enumC4496k1Arr = {enumC4496k1, enumC4496k12, enumC4496k13, enumC4496k14, enumC4496k15, enumC4496k16, enumC4496k17, enumC4496k18, enumC4496k19};
        $VALUES = enumC4496k1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4496k1Arr);
        Companion = new C4493j1();
    }

    public EnumC4496k1(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4496k1 valueOf(String str) {
        return (EnumC4496k1) Enum.valueOf(EnumC4496k1.class, str);
    }

    public static EnumC4496k1[] values() {
        return (EnumC4496k1[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
