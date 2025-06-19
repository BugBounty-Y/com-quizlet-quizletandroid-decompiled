package com.perimeterx.mobile_sdk;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class b {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[PerimeterXErrorCode.values().length];
        try {
            iArr[PerimeterXErrorCode.MISSING_APP_ID.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[PerimeterXErrorCode.INVALID_APP_ID.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[PerimeterXErrorCode.START_NOT_CALLED_ON_MAIN_THREAD.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[PerimeterXErrorCode.START_CALLED_MORE_THAN_ONCE.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[PerimeterXErrorCode.TOKEN_WAS_NOT_GENERATED.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr[PerimeterXErrorCode.START_WAS_NOT_CALLED.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr[PerimeterXErrorCode.INTERNAL_ERROR.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        a = iArr;
    }
}
