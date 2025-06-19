package com.quizlet.quizletandroid.ui.activitycenter.views;

import com.braze.enums.CardType;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[CardType.values().length];
        try {
            iArr[CardType.SHORT_NEWS.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[CardType.TEXT_ANNOUNCEMENT.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
