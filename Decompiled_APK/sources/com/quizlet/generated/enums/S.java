package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class S {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ S[] $VALUES;
    public static final S CONTROL_VARIANT;

    @NotNull
    public static final Q Companion;
    public static final S EXPERIMENT_VARIANT;
    public static final S EXPERIMENT_VARIANT_SET_IN_TEACHER_CLASS;
    public static final S HAS_QUIZLET_PLUS;
    public static final S IS_IN_CLASS_SESSION;
    public static final S NOT_ELIGIBLE_FOR_EXPERIMENT;
    public static final S NOT_ENROLLED_IN_EXPERIMENT;
    public static final S QUALIFIES_FOR_METERING;
    public static final S REFERRAL_EXPIRED;
    public static final S REFERRED_BY_PLUS_USER;
    public static final S UNKNOWN;
    private final int value;

    static {
        S s = new S("UNKNOWN", 0, 0);
        UNKNOWN = s;
        S s2 = new S("HAS_QUIZLET_PLUS", 1, 1);
        HAS_QUIZLET_PLUS = s2;
        S s3 = new S("NOT_ENROLLED_IN_EXPERIMENT", 2, 2);
        NOT_ENROLLED_IN_EXPERIMENT = s3;
        S s4 = new S("CONTROL_VARIANT", 3, 3);
        CONTROL_VARIANT = s4;
        S s5 = new S("EXPERIMENT_VARIANT", 4, 4);
        EXPERIMENT_VARIANT = s5;
        S s6 = new S("EXPERIMENT_VARIANT_SET_IN_TEACHER_CLASS", 5, 5);
        EXPERIMENT_VARIANT_SET_IN_TEACHER_CLASS = s6;
        S s7 = new S("NOT_ELIGIBLE_FOR_EXPERIMENT", 6, 6);
        NOT_ELIGIBLE_FOR_EXPERIMENT = s7;
        S s8 = new S("QUALIFIES_FOR_METERING", 7, 7);
        QUALIFIES_FOR_METERING = s8;
        S s9 = new S("IS_IN_CLASS_SESSION", 8, 8);
        IS_IN_CLASS_SESSION = s9;
        S s10 = new S("REFERRED_BY_PLUS_USER", 9, 9);
        REFERRED_BY_PLUS_USER = s10;
        S s11 = new S("REFERRAL_EXPIRED", 10, 10);
        REFERRAL_EXPIRED = s11;
        S[] sArr = {s, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11};
        $VALUES = sArr;
        $ENTRIES = AbstractC3328d.f(sArr);
        Companion = new Q();
    }

    public S(String str, int i, int i2) {
        this.value = i2;
    }

    public static S valueOf(String str) {
        return (S) Enum.valueOf(S.class, str);
    }

    public static S[] values() {
        return (S[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
