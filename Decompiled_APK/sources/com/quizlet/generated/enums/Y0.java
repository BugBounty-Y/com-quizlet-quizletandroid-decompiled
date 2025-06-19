package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class Y0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Y0[] $VALUES;
    public static final Y0 ALL;

    @NotNull
    public static final X0 Companion;
    public static final Y0 PLUS;
    public static final Y0 STUDENT;
    public static final Y0 TEACHER;
    public static final Y0 VERIFIED_CREATOR;

    @NotNull
    private final String value;

    static {
        Y0 y0 = new Y0("ALL", 0, OTCCPAGeolocationConstants.ALL);
        ALL = y0;
        Y0 y02 = new Y0("STUDENT", 1, "student");
        STUDENT = y02;
        Y0 y03 = new Y0("PLUS", 2, "plus");
        PLUS = y03;
        Y0 y04 = new Y0("TEACHER", 3, "teacher");
        TEACHER = y04;
        Y0 y05 = new Y0("VERIFIED_CREATOR", 4, "verifiedCreator");
        VERIFIED_CREATOR = y05;
        Y0[] y0Arr = {y0, y02, y03, y04, y05};
        $VALUES = y0Arr;
        $ENTRIES = AbstractC3328d.f(y0Arr);
        Companion = new X0();
    }

    public Y0(String str, int i, String str2) {
        this.value = str2;
    }

    public static Y0 valueOf(String str) {
        return (Y0) Enum.valueOf(Y0.class, str);
    }

    public static Y0[] values() {
        return (Y0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
