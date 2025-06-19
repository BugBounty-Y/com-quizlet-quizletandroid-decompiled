package com.quizlet.search.data.blended;

import com.quizlet.generated.enums.W0;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class j {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[W0.values().length];
        try {
            iArr[W0.STANDARDIZED_EXAM.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[W0.LITERATURE_GUIDE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[W0.SUBJECT.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
    }
}
