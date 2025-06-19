package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class Y {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Y[] $VALUES;
    public static final Y CONTINUE_FLASHCARDS;

    @NotNull
    public static final X Companion;
    public static final Y FLASHCARDS_TO_LEARN;
    public static final Y FLASHCARDS_TO_TEST;
    public static final Y RESTART_FLASHCARDS;
    public static final Y RETAKE_TEST;
    public static final Y REVIEW_FLASHCARDS;
    public static final Y SORT_FLASHCARDS;
    public static final Y TAKE_NEW_TEST;
    public static final Y TAKE_NEW_TEST_MISSED_UNSTUDIED;
    public static final Y TEST_TO_FLASHCARDS;
    public static final Y TEST_TO_LEARN;

    @NotNull
    private final String value;

    static {
        Y y = new Y("CONTINUE_FLASHCARDS", 0, "continue_flashcards");
        CONTINUE_FLASHCARDS = y;
        Y y2 = new Y("FLASHCARDS_TO_LEARN", 1, "flashcards_to_learn");
        FLASHCARDS_TO_LEARN = y2;
        Y y3 = new Y("FLASHCARDS_TO_TEST", 2, "flashcards_to_test");
        FLASHCARDS_TO_TEST = y3;
        Y y4 = new Y("RESTART_FLASHCARDS", 3, "restart_flashcards");
        RESTART_FLASHCARDS = y4;
        Y y5 = new Y("RETAKE_TEST", 4, "retake_test");
        RETAKE_TEST = y5;
        Y y6 = new Y("REVIEW_FLASHCARDS", 5, "review_flashcards");
        REVIEW_FLASHCARDS = y6;
        Y y7 = new Y("SORT_FLASHCARDS", 6, "sort_flashcards");
        SORT_FLASHCARDS = y7;
        Y y8 = new Y("TAKE_NEW_TEST", 7, "take_new_test");
        TAKE_NEW_TEST = y8;
        Y y9 = new Y("TEST_TO_FLASHCARDS", 8, "test_to_flashcards");
        TEST_TO_FLASHCARDS = y9;
        Y y10 = new Y("TEST_TO_LEARN", 9, "test_to_learn");
        TEST_TO_LEARN = y10;
        Y y11 = new Y("TAKE_NEW_TEST_MISSED_UNSTUDIED", 10, "take_new_test_missed_unstudied");
        TAKE_NEW_TEST_MISSED_UNSTUDIED = y11;
        Y[] yArr = {y, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11};
        $VALUES = yArr;
        $ENTRIES = AbstractC3328d.f(yArr);
        Companion = new X();
    }

    public Y(String str, int i, String str2) {
        this.value = str2;
    }

    public static Y valueOf(String str) {
        return (Y) Enum.valueOf(Y.class, str);
    }

    public static Y[] values() {
        return (Y[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
