package com.quizlet.features.setpage.utils.setpermissions;

import com.quizlet.features.setpage.usecases.g;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class d {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[g.values().length];
        try {
            g gVar = g.a;
            iArr[0] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            g gVar2 = g.a;
            iArr[1] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
