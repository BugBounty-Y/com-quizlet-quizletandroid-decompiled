package com.quizlet.features.practicetest.results.usecase;

import com.quizlet.generated.enums.EnumC4501m0;
import com.quizlet.generated.enums.EnumC4533y0;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[EnumC4533y0.values().length];
        try {
            iArr[EnumC4533y0.MCQ_WITH_SINGLE_ANSWER.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
        int[] iArr2 = new int[EnumC4501m0.values().length];
        try {
            iArr2[EnumC4501m0.CORRECT.ordinal()] = 1;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr2[EnumC4501m0.INCORRECT.ordinal()] = 2;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr2[EnumC4501m0.SKIPPED.ordinal()] = 3;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr2[EnumC4501m0.OVERRIDDEN_CORRECT.ordinal()] = 4;
        } catch (NoSuchFieldError unused6) {
        }
        b = iArr2;
    }
}
