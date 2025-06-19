package com.quizlet.remote.model.studymaterial;

import com.quizlet.generated.enums.y1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[y1.values().length];
        try {
            iArr[y1.SET.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[y1.FOLDER.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[y1.TEXTBOOK.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[y1.TEXTBOOK_EXERCISE.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[y1.EXPLANATION_QUESTION.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr[y1.NOTE.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr[y1.PRACTICE_TEST.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr[y1.QUESTION_BANK.ordinal()] = 8;
        } catch (NoSuchFieldError unused8) {
        }
        a = iArr;
    }
}
