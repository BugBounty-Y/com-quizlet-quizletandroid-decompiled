package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.y0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4533y0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4533y0[] $VALUES;

    @NotNull
    public static final C4531x0 Companion;
    public static final EnumC4533y0 FITB_MULTIPLE_BLANKS;
    public static final EnumC4533y0 FITB_SINGLE_BLANK;
    public static final EnumC4533y0 MCQ_WITH_MULTIPLE_ANSWERS;
    public static final EnumC4533y0 MCQ_WITH_SINGLE_ANSWER;
    public static final EnumC4533y0 QUESTION_WITH_LONG_FREE_RESPONSE;
    public static final EnumC4533y0 QUESTION_WITH_SHORT_FREE_RESPONSE;
    public static final EnumC4533y0 TRUE_OR_FALSE;

    @NotNull
    private final String value;

    static {
        EnumC4533y0 enumC4533y0 = new EnumC4533y0("TRUE_OR_FALSE", 0, "true_or_false");
        TRUE_OR_FALSE = enumC4533y0;
        EnumC4533y0 enumC4533y02 = new EnumC4533y0("MCQ_WITH_SINGLE_ANSWER", 1, "mcq_with_single_answer");
        MCQ_WITH_SINGLE_ANSWER = enumC4533y02;
        EnumC4533y0 enumC4533y03 = new EnumC4533y0("MCQ_WITH_MULTIPLE_ANSWERS", 2, "mcq_with_multiple_answers");
        MCQ_WITH_MULTIPLE_ANSWERS = enumC4533y03;
        EnumC4533y0 enumC4533y04 = new EnumC4533y0("FITB_SINGLE_BLANK", 3, "fitb_single_blank");
        FITB_SINGLE_BLANK = enumC4533y04;
        EnumC4533y0 enumC4533y05 = new EnumC4533y0("FITB_MULTIPLE_BLANKS", 4, "fitb_multiple_blanks");
        FITB_MULTIPLE_BLANKS = enumC4533y05;
        EnumC4533y0 enumC4533y06 = new EnumC4533y0("QUESTION_WITH_SHORT_FREE_RESPONSE", 5, "question_with_short_free_response");
        QUESTION_WITH_SHORT_FREE_RESPONSE = enumC4533y06;
        EnumC4533y0 enumC4533y07 = new EnumC4533y0("QUESTION_WITH_LONG_FREE_RESPONSE", 6, "question_with_long_free_response");
        QUESTION_WITH_LONG_FREE_RESPONSE = enumC4533y07;
        EnumC4533y0[] enumC4533y0Arr = {enumC4533y0, enumC4533y02, enumC4533y03, enumC4533y04, enumC4533y05, enumC4533y06, enumC4533y07};
        $VALUES = enumC4533y0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4533y0Arr);
        Companion = new C4531x0();
    }

    public EnumC4533y0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4533y0 valueOf(String str) {
        return (EnumC4533y0) Enum.valueOf(EnumC4533y0.class, str);
    }

    public static EnumC4533y0[] values() {
        return (EnumC4533y0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
