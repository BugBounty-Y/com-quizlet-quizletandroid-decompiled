package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class L {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ L[] $VALUES;
    public static final L AD_MODAL;
    public static final L CHECKPOINT;

    @NotNull
    public static final K Companion;
    public static final L END;
    public static final L FEEDBACK;
    public static final L LOADING;
    public static final L ONBOARDING;
    public static final L PARTIAL_ANSWERS_GRADING_PROMPT;
    public static final L QUESTION;
    public static final L SELF_GRADE_PROMPT;
    public static final L TASK_COMPLETION_CHECKPOINT_NON_PLUS;
    public static final L TASK_COMPLETION_CHECKPOINT_PLUS;
    public static final L TASK_MEASURE_CONFIDENCE;
    public static final L TASK_ROUND_CHECKPOINT;
    public static final L TASK_SEQUENCE_COMPLETION_CHECKPOINT_NON_PLUS;
    public static final L TASK_SEQUENCE_COMPLETION_CHECKPOINT_PLUS;
    private final int value;

    static {
        L l = new L("AD_MODAL", 0, 0);
        AD_MODAL = l;
        L l2 = new L("LOADING", 1, 1);
        LOADING = l2;
        L l3 = new L("ONBOARDING", 2, 2);
        ONBOARDING = l3;
        L l4 = new L("QUESTION", 3, 3);
        QUESTION = l4;
        L l5 = new L("FEEDBACK", 4, 4);
        FEEDBACK = l5;
        L l6 = new L("CHECKPOINT", 5, 5);
        CHECKPOINT = l6;
        L l7 = new L("PARTIAL_ANSWERS_GRADING_PROMPT", 6, 6);
        PARTIAL_ANSWERS_GRADING_PROMPT = l7;
        L l8 = new L("SELF_GRADE_PROMPT", 7, 7);
        SELF_GRADE_PROMPT = l8;
        L l9 = new L("END", 8, 8);
        END = l9;
        L l10 = new L("TASK_ROUND_CHECKPOINT", 9, 9);
        TASK_ROUND_CHECKPOINT = l10;
        L l11 = new L("TASK_COMPLETION_CHECKPOINT_PLUS", 10, 10);
        TASK_COMPLETION_CHECKPOINT_PLUS = l11;
        L l12 = new L("TASK_COMPLETION_CHECKPOINT_NON_PLUS", 11, 11);
        TASK_COMPLETION_CHECKPOINT_NON_PLUS = l12;
        L l13 = new L("TASK_SEQUENCE_COMPLETION_CHECKPOINT_PLUS", 12, 12);
        TASK_SEQUENCE_COMPLETION_CHECKPOINT_PLUS = l13;
        L l14 = new L("TASK_SEQUENCE_COMPLETION_CHECKPOINT_NON_PLUS", 13, 13);
        TASK_SEQUENCE_COMPLETION_CHECKPOINT_NON_PLUS = l14;
        L l15 = new L("TASK_MEASURE_CONFIDENCE", 14, 14);
        TASK_MEASURE_CONFIDENCE = l15;
        L[] lArr = {l, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15};
        $VALUES = lArr;
        $ENTRIES = AbstractC3328d.f(lArr);
        Companion = new K();
    }

    public L(String str, int i, int i2) {
        this.value = i2;
    }

    public static L valueOf(String str) {
        return (L) Enum.valueOf(L.class, str);
    }

    public static L[] values() {
        return (L[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
