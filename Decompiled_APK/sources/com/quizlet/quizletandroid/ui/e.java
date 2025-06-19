package com.quizlet.quizletandroid.ui;

import com.quizlet.generated.enums.EnumC4495k0;
import com.quizlet.generated.enums.S1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class e {
    public static final /* synthetic */ int[] a;
    public static final /* synthetic */ int[] b;

    static {
        int[] iArr = new int[S1.values().length];
        try {
            iArr[S1.STUDY_DUE_USER_STUDYABLE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[S1.STUDY_DUE_FOLDER.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[S1.STUDY_NEXT_DAY_REMINDER.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[S1.REENGAGEMENT_NOTIFICATION.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[S1.RECOMMENDED_SET.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        a = iArr;
        int[] iArr2 = new int[EnumC4495k0.values().length];
        try {
            iArr2[EnumC4495k0.HOME.ordinal()] = 1;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[EnumC4495k0.CREATE_SET.ordinal()] = 2;
        } catch (NoSuchFieldError unused7) {
        }
        b = iArr2;
    }
}
