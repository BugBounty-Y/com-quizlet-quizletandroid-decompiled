package com.quizlet.shared.utils;

import assistantMode.enums.QuestionType$Companion;
import assistantMode.enums.k;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[k.values().length];
        try {
            QuestionType$Companion questionType$Companion = k.Companion;
            iArr[5] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            QuestionType$Companion questionType$Companion2 = k.Companion;
            iArr[3] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            QuestionType$Companion questionType$Companion3 = k.Companion;
            iArr[6] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            QuestionType$Companion questionType$Companion4 = k.Companion;
            iArr[10] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            QuestionType$Companion questionType$Companion5 = k.Companion;
            iArr[12] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            QuestionType$Companion questionType$Companion6 = k.Companion;
            iArr[11] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        a = iArr;
    }
}
