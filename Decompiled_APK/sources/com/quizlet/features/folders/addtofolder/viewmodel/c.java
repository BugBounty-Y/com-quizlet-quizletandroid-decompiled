package com.quizlet.features.folders.addtofolder.viewmodel;

import com.quizlet.features.folders.addtofolder.data.o;
import com.quizlet.features.folders.addtofolder.data.t;
import com.quizlet.generated.enums.y1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class c {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[t.values().length];
        try {
            iArr[0] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            t tVar = t.a;
            iArr[1] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
        int[] iArr2 = new int[y1.values().length];
        try {
            iArr2[y1.SET.ordinal()] = 1;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr2[y1.TEXTBOOK.ordinal()] = 2;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr2[y1.TEXTBOOK_EXERCISE.ordinal()] = 3;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr2[y1.EXPLANATION_QUESTION.ordinal()] = 4;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[y1.NOTE.ordinal()] = 5;
        } catch (NoSuchFieldError unused7) {
        }
        b = iArr2;
        int[] iArr3 = new int[o.values().length];
        try {
            iArr3[0] = 1;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            o oVar = o.a;
            iArr3[1] = 2;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            o oVar2 = o.a;
            iArr3[2] = 3;
        } catch (NoSuchFieldError unused10) {
        }
    }
}
