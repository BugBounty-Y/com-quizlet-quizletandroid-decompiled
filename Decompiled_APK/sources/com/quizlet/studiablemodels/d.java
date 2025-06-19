package com.quizlet.studiablemodels;

import com.quizlet.generated.enums.P;
import com.quizlet.shared.enums.MeteredEventType$Companion;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class d {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[P.values().length];
        try {
            iArr[P.EXPLANATION_VIEW.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[P.LEARN_CHECKPOINT.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[P.TEST_SUBMISSION.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[P.LEARN_CHECKPOINT_REWARD.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[P.QCHAT_MESSAGE.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr[P.MAGIC_NOTES_UPLOAD.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr[P.LEARN_CHECKPOINT_USER.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr[P.PRACTICE_TEST_UPLOAD.ordinal()] = 8;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            iArr[P.PRACTICE_TEST_CONSUMPTION.ordinal()] = 9;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            iArr[P.PRACTICE_TEST_CONSUMPTION_USER.ordinal()] = 10;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            iArr[P.TEST_SUBMISSION_USER.ordinal()] = 11;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            iArr[P.TEXTBOOK_EXERCISE_USER.ordinal()] = 12;
        } catch (NoSuchFieldError unused12) {
        }
        a = iArr;
        int[] iArr2 = new int[com.quizlet.shared.enums.h.values().length];
        try {
            iArr2[0] = 1;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            MeteredEventType$Companion meteredEventType$Companion = com.quizlet.shared.enums.h.Companion;
            iArr2[1] = 2;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            MeteredEventType$Companion meteredEventType$Companion2 = com.quizlet.shared.enums.h.Companion;
            iArr2[2] = 3;
        } catch (NoSuchFieldError unused15) {
        }
    }
}
