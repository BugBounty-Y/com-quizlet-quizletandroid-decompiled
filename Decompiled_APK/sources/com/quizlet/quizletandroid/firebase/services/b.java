package com.quizlet.quizletandroid.firebase.services;

import com.quizlet.generated.enums.S1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[S1.values().length];
        try {
            iArr[S1.STUDY_DUE_USER_STUDYABLE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[S1.RECOMMENDED_SET.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[S1.STUDY_DUE_FOLDER.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[S1.NEW_USER_NOTIFICATION.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        a = iArr;
    }
}
