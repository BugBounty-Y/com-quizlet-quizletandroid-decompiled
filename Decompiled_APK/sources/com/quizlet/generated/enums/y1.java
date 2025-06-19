package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class y1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ y1[] $VALUES;

    @NotNull
    public static final x1 Companion;
    public static final y1 EXPLANATION_QUESTION;
    public static final y1 FOLDER;
    public static final y1 NOTE;
    public static final y1 PRACTICE_TEST;
    public static final y1 QUESTION_BANK;
    public static final y1 SET;
    public static final y1 TEXTBOOK;
    public static final y1 TEXTBOOK_EXERCISE;
    private final int value;

    static {
        y1 y1Var = new y1("SET", 0, 1);
        SET = y1Var;
        y1 y1Var2 = new y1("FOLDER", 1, 2);
        FOLDER = y1Var2;
        y1 y1Var3 = new y1("TEXTBOOK", 2, 3);
        TEXTBOOK = y1Var3;
        y1 y1Var4 = new y1("TEXTBOOK_EXERCISE", 3, 4);
        TEXTBOOK_EXERCISE = y1Var4;
        y1 y1Var5 = new y1("EXPLANATION_QUESTION", 4, 5);
        EXPLANATION_QUESTION = y1Var5;
        y1 y1Var6 = new y1("NOTE", 5, 6);
        NOTE = y1Var6;
        y1 y1Var7 = new y1("PRACTICE_TEST", 6, 7);
        PRACTICE_TEST = y1Var7;
        y1 y1Var8 = new y1("QUESTION_BANK", 7, 8);
        QUESTION_BANK = y1Var8;
        y1[] y1VarArr = {y1Var, y1Var2, y1Var3, y1Var4, y1Var5, y1Var6, y1Var7, y1Var8};
        $VALUES = y1VarArr;
        $ENTRIES = AbstractC3328d.f(y1VarArr);
        Companion = new x1();
    }

    public y1(String str, int i, int i2) {
        this.value = i2;
    }

    public static kotlin.enums.a a() {
        return $ENTRIES;
    }

    public static y1 valueOf(String str) {
        return (y1) Enum.valueOf(y1.class, str);
    }

    public static y1[] values() {
        return (y1[]) $VALUES.clone();
    }

    public final int b() {
        return this.value;
    }
}
