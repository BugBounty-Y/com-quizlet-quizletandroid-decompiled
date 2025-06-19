package com.quizlet.features.questiontypes.composables;

import androidx.lifecycle.A;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class e {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[A.values().length];
        try {
            iArr[A.ON_START.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[A.ON_STOP.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
