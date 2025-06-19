package com.quizlet.quizletandroid.ui.studymodes.grader;

import com.quizlet.generated.enums.A1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[A1.values().length];
        try {
            iArr[A1.LEARNING_ASSISTANT.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[A1.MOBILE_WRITE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[A1.TEST.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
    }
}
