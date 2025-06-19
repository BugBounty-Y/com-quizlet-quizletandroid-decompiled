package com.quizlet.quizletandroid.ui.studymodes.write;

import com.quizlet.generated.enums.O1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class i {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[O1.values().length];
        a = iArr;
        try {
            iArr[O1.WORD.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[O1.DEFINITION.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
    }
}
