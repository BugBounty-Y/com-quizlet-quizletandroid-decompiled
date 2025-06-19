package com.perimeterx.mobile_sdk.business_logic;

import com.perimeterx.mobile_sdk.api_data.f;
import com.perimeterx.mobile_sdk.main.PXPolicyUrlRequestInterceptionType;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[PXPolicyUrlRequestInterceptionType.values().length];
        try {
            iArr[PXPolicyUrlRequestInterceptionType.NONE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[PXPolicyUrlRequestInterceptionType.INTERCEPT_WITH_DELAYED_RESPONSE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[PXPolicyUrlRequestInterceptionType.INTERCEPT_AND_RETRY_REQUEST.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[PXPolicyUrlRequestInterceptionType.INTERCEPT.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        a = iArr;
        int[] iArr2 = new int[f.values().length];
        try {
            iArr2[2] = 1;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            f fVar = f.a;
            iArr2[3] = 2;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            f fVar2 = f.a;
            iArr2[0] = 3;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            f fVar3 = f.a;
            iArr2[1] = 4;
        } catch (NoSuchFieldError unused8) {
        }
    }
}
