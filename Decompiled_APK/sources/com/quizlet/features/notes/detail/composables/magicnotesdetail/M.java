package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import com.quizlet.data.model.EnumC4175w;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class M {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[EnumC4175w.values().length];
        try {
            iArr[EnumC4175w.COMPLETE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[EnumC4175w.PENDING.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
