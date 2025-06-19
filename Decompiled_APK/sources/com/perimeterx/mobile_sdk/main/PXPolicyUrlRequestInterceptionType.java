package com.perimeterx.mobile_sdk.main;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXPolicyUrlRequestInterceptionType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ PXPolicyUrlRequestInterceptionType[] $VALUES;
    public static final PXPolicyUrlRequestInterceptionType NONE = new PXPolicyUrlRequestInterceptionType("NONE", 0);
    public static final PXPolicyUrlRequestInterceptionType INTERCEPT = new PXPolicyUrlRequestInterceptionType("INTERCEPT", 1);
    public static final PXPolicyUrlRequestInterceptionType INTERCEPT_WITH_DELAYED_RESPONSE = new PXPolicyUrlRequestInterceptionType("INTERCEPT_WITH_DELAYED_RESPONSE", 2);
    public static final PXPolicyUrlRequestInterceptionType INTERCEPT_AND_RETRY_REQUEST = new PXPolicyUrlRequestInterceptionType("INTERCEPT_AND_RETRY_REQUEST", 3);

    private static final /* synthetic */ PXPolicyUrlRequestInterceptionType[] $values() {
        return new PXPolicyUrlRequestInterceptionType[]{NONE, INTERCEPT, INTERCEPT_WITH_DELAYED_RESPONSE, INTERCEPT_AND_RETRY_REQUEST};
    }

    static {
        PXPolicyUrlRequestInterceptionType[] pXPolicyUrlRequestInterceptionTypeArr$values = $values();
        $VALUES = pXPolicyUrlRequestInterceptionTypeArr$values;
        $ENTRIES = AbstractC3328d.f(pXPolicyUrlRequestInterceptionTypeArr$values);
    }

    private PXPolicyUrlRequestInterceptionType(String str, int i) {
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static PXPolicyUrlRequestInterceptionType valueOf(String str) {
        return (PXPolicyUrlRequestInterceptionType) Enum.valueOf(PXPolicyUrlRequestInterceptionType.class, str);
    }

    public static PXPolicyUrlRequestInterceptionType[] values() {
        return (PXPolicyUrlRequestInterceptionType[]) $VALUES.clone();
    }
}
