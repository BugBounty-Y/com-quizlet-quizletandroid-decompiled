package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class P {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ P[] $VALUES;

    @NotNull
    public static final O Companion;
    public static final P EXPLANATION_VIEW;
    public static final P LEARN_CHECKPOINT;
    public static final P LEARN_CHECKPOINT_REWARD;
    public static final P LEARN_CHECKPOINT_USER;
    public static final P MAGIC_NOTES_UPLOAD;
    public static final P PRACTICE_TEST_CONSUMPTION;
    public static final P PRACTICE_TEST_CONSUMPTION_USER;
    public static final P PRACTICE_TEST_UPLOAD;
    public static final P QCHAT_MESSAGE;
    public static final P TEST_SUBMISSION;
    public static final P TEST_SUBMISSION_USER;
    public static final P TEXTBOOK_EXERCISE_USER;
    private final int value;

    static {
        P p = new P("EXPLANATION_VIEW", 0, 0);
        EXPLANATION_VIEW = p;
        P p2 = new P("LEARN_CHECKPOINT", 1, 1);
        LEARN_CHECKPOINT = p2;
        P p3 = new P("TEST_SUBMISSION", 2, 2);
        TEST_SUBMISSION = p3;
        P p4 = new P("LEARN_CHECKPOINT_REWARD", 3, 3);
        LEARN_CHECKPOINT_REWARD = p4;
        P p5 = new P("QCHAT_MESSAGE", 4, 4);
        QCHAT_MESSAGE = p5;
        P p6 = new P("MAGIC_NOTES_UPLOAD", 5, 5);
        MAGIC_NOTES_UPLOAD = p6;
        P p7 = new P("LEARN_CHECKPOINT_USER", 6, 6);
        LEARN_CHECKPOINT_USER = p7;
        P p8 = new P("PRACTICE_TEST_UPLOAD", 7, 7);
        PRACTICE_TEST_UPLOAD = p8;
        P p9 = new P("PRACTICE_TEST_CONSUMPTION", 8, 8);
        PRACTICE_TEST_CONSUMPTION = p9;
        P p10 = new P("PRACTICE_TEST_CONSUMPTION_USER", 9, 9);
        PRACTICE_TEST_CONSUMPTION_USER = p10;
        P p11 = new P("TEST_SUBMISSION_USER", 10, 10);
        TEST_SUBMISSION_USER = p11;
        P p12 = new P("TEXTBOOK_EXERCISE_USER", 11, 11);
        TEXTBOOK_EXERCISE_USER = p12;
        P[] pArr = {p, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12};
        $VALUES = pArr;
        $ENTRIES = AbstractC3328d.f(pArr);
        Companion = new O();
    }

    public P(String str, int i, int i2) {
        this.value = i2;
    }

    public static P valueOf(String str) {
        return (P) Enum.valueOf(P.class, str);
    }

    public static P[] values() {
        return (P[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
