package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.g1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4484g1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4484g1[] $VALUES;
    public static final EnumC4484g1 ALL;

    @NotNull
    public static final C4481f1 Companion;
    public static final EnumC4484g1 GREATER_THAN_FIFTY;
    public static final EnumC4484g1 LESS_THAN_TWENTY;
    public static final EnumC4484g1 TWENTY_TO_FORTY_NINE;

    @NotNull
    private final String value;

    static {
        EnumC4484g1 enumC4484g1 = new EnumC4484g1("ALL", 0, OTCCPAGeolocationConstants.ALL);
        ALL = enumC4484g1;
        EnumC4484g1 enumC4484g12 = new EnumC4484g1("LESS_THAN_TWENTY", 1, "lessThanTwenty");
        LESS_THAN_TWENTY = enumC4484g12;
        EnumC4484g1 enumC4484g13 = new EnumC4484g1("TWENTY_TO_FORTY_NINE", 2, "twentyToFortyNine");
        TWENTY_TO_FORTY_NINE = enumC4484g13;
        EnumC4484g1 enumC4484g14 = new EnumC4484g1("GREATER_THAN_FIFTY", 3, "greaterThanFifty");
        GREATER_THAN_FIFTY = enumC4484g14;
        EnumC4484g1[] enumC4484g1Arr = {enumC4484g1, enumC4484g12, enumC4484g13, enumC4484g14};
        $VALUES = enumC4484g1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4484g1Arr);
        Companion = new C4481f1();
    }

    public EnumC4484g1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4484g1 valueOf(String str) {
        return (EnumC4484g1) Enum.valueOf(EnumC4484g1.class, str);
    }

    public static EnumC4484g1[] values() {
        return (EnumC4484g1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
