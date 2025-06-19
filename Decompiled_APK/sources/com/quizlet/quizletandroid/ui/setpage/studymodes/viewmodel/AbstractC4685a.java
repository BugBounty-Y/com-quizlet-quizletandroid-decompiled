package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.generated.enums.A1;

/* renamed from: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract /* synthetic */ class AbstractC4685a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[A1.values().length];
        try {
            iArr[A1.LEARNING_ASSISTANT.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[A1.FLASHCARDS.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
