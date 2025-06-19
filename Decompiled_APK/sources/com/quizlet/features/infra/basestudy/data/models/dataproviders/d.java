package com.quizlet.features.infra.basestudy.data.models.dataproviders;

import com.quizlet.generated.enums.G1;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class d {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[G1.values().length];
        a = iArr;
        try {
            iArr[G1.SET.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            a[G1.FOLDER.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
    }
}
