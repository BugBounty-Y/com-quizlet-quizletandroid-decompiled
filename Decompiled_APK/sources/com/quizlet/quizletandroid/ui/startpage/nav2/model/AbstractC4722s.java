package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.quizlet.generated.enums.w1;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract /* synthetic */ class AbstractC4722s {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[w1.values().length];
        try {
            iArr[w1.BEHAVIORAL_REC.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[w1.EDU_REC.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[w1.AGE_LOCATION_REC.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        a = iArr;
    }
}
