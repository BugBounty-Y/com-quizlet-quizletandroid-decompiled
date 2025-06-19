package com.quizlet.generated.enums;

import com.comscore.android.id.IdHelperAndroid;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.i1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4490i1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4490i1[] $VALUES;
    public static final EnumC4490i1 ALL;

    @NotNull
    public static final C4487h1 Companion;
    public static final EnumC4490i1 DIAGRAMS;
    public static final EnumC4490i1 IMAGES;
    public static final EnumC4490i1 NONE;

    @NotNull
    private final String value;

    static {
        EnumC4490i1 enumC4490i1 = new EnumC4490i1("ALL", 0, OTCCPAGeolocationConstants.ALL);
        ALL = enumC4490i1;
        EnumC4490i1 enumC4490i12 = new EnumC4490i1("IMAGES", 1, "images");
        IMAGES = enumC4490i12;
        EnumC4490i1 enumC4490i13 = new EnumC4490i1("DIAGRAMS", 2, "diagrams");
        DIAGRAMS = enumC4490i13;
        EnumC4490i1 enumC4490i14 = new EnumC4490i1("NONE", 3, IdHelperAndroid.NO_ID_AVAILABLE);
        NONE = enumC4490i14;
        EnumC4490i1[] enumC4490i1Arr = {enumC4490i1, enumC4490i12, enumC4490i13, enumC4490i14};
        $VALUES = enumC4490i1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4490i1Arr);
        Companion = new C4487h1();
    }

    public EnumC4490i1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4490i1 valueOf(String str) {
        return (EnumC4490i1) Enum.valueOf(EnumC4490i1.class, str);
    }

    public static EnumC4490i1[] values() {
        return (EnumC4490i1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
