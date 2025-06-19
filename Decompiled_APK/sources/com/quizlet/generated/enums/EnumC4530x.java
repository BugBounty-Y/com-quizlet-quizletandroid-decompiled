package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4530x {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4530x[] $VALUES;

    @NotNull
    public static final C4528w Companion;
    public static final EnumC4530x FIZZ_UPGRADE;
    public static final EnumC4530x LIMIT_MWEB_STUDYING;
    public static final EnumC4530x MINIFC_QPLUS_INCENTIVE;
    public static final EnumC4530x ONRAMPS_MODAL_SET_PAGE;

    @NotNull
    private final String value;

    static {
        EnumC4530x enumC4530x = new EnumC4530x("ONRAMPS_MODAL_SET_PAGE", 0, "onramps_modal_set_page");
        ONRAMPS_MODAL_SET_PAGE = enumC4530x;
        EnumC4530x enumC4530x2 = new EnumC4530x("MINIFC_QPLUS_INCENTIVE", 1, "minifc_qplus_incentive");
        MINIFC_QPLUS_INCENTIVE = enumC4530x2;
        EnumC4530x enumC4530x3 = new EnumC4530x("LIMIT_MWEB_STUDYING", 2, "limit_mweb_studying");
        LIMIT_MWEB_STUDYING = enumC4530x3;
        EnumC4530x enumC4530x4 = new EnumC4530x("FIZZ_UPGRADE", 3, "fizz_upgrade");
        FIZZ_UPGRADE = enumC4530x4;
        EnumC4530x[] enumC4530xArr = {enumC4530x, enumC4530x2, enumC4530x3, enumC4530x4};
        $VALUES = enumC4530xArr;
        $ENTRIES = AbstractC3328d.f(enumC4530xArr);
        Companion = new C4528w();
    }

    public EnumC4530x(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4530x valueOf(String str) {
        return (EnumC4530x) Enum.valueOf(EnumC4530x.class, str);
    }

    public static EnumC4530x[] values() {
        return (EnumC4530x[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
