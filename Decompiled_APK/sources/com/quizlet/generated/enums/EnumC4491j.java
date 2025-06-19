package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4491j {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4491j[] $VALUES;

    @NotNull
    public static final C4488i Companion;
    public static final EnumC4491j EXPLANATIONS;
    public static final EnumC4491j FLASHCARDS_MODE;
    public static final EnumC4491j LEARN_MODE;
    public static final EnumC4491j MATCH_MODE;
    public static final EnumC4491j PRACTICE_TEST;
    public static final EnumC4491j SETS;
    public static final EnumC4491j STUDY_GUIDES;
    public static final EnumC4491j TEST_MODE;

    @NotNull
    private final String value;

    static {
        EnumC4491j enumC4491j = new EnumC4491j("EXPLANATIONS", 0, "Explanations");
        EXPLANATIONS = enumC4491j;
        EnumC4491j enumC4491j2 = new EnumC4491j("FLASHCARDS_MODE", 1, "FlashcardsMode");
        FLASHCARDS_MODE = enumC4491j2;
        EnumC4491j enumC4491j3 = new EnumC4491j("LEARN_MODE", 2, "LearnMode");
        LEARN_MODE = enumC4491j3;
        EnumC4491j enumC4491j4 = new EnumC4491j("MATCH_MODE", 3, "MatchMode");
        MATCH_MODE = enumC4491j4;
        EnumC4491j enumC4491j5 = new EnumC4491j("SETS", 4, "Sets");
        SETS = enumC4491j5;
        EnumC4491j enumC4491j6 = new EnumC4491j("TEST_MODE", 5, "TestMode");
        TEST_MODE = enumC4491j6;
        EnumC4491j enumC4491j7 = new EnumC4491j("STUDY_GUIDES", 6, "StudyGuides");
        STUDY_GUIDES = enumC4491j7;
        EnumC4491j enumC4491j8 = new EnumC4491j("PRACTICE_TEST", 7, "PracticeTest");
        PRACTICE_TEST = enumC4491j8;
        EnumC4491j[] enumC4491jArr = {enumC4491j, enumC4491j2, enumC4491j3, enumC4491j4, enumC4491j5, enumC4491j6, enumC4491j7, enumC4491j8};
        $VALUES = enumC4491jArr;
        $ENTRIES = AbstractC3328d.f(enumC4491jArr);
        Companion = new C4488i();
    }

    public EnumC4491j(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4491j valueOf(String str) {
        return (EnumC4491j) Enum.valueOf(EnumC4491j.class, str);
    }

    public static EnumC4491j[] values() {
        return (EnumC4491j[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
