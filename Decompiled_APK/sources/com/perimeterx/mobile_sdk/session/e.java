package com.perimeterx.mobile_sdk.session;

import com.perimeterx.mobile_sdk.main.PXStorageMethod;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class e {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[PXStorageMethod.values().length];
        try {
            iArr[PXStorageMethod.SHARED_PREFERENCES.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[PXStorageMethod.DATA_STORE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        a = iArr;
    }
}
