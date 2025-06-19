package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.i0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4489i0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4489i0[] $VALUES;

    @NotNull
    public static final C4486h0 Companion;
    public static final EnumC4489i0 IMAGE;
    public static final EnumC4489i0 TEXT;
    public static final EnumC4489i0 VIDEO;

    @NotNull
    private final String value;

    static {
        EnumC4489i0 enumC4489i0 = new EnumC4489i0("IMAGE", 0, "image");
        IMAGE = enumC4489i0;
        EnumC4489i0 enumC4489i02 = new EnumC4489i0("TEXT", 1, "text");
        TEXT = enumC4489i02;
        EnumC4489i0 enumC4489i03 = new EnumC4489i0("VIDEO", 2, com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO);
        VIDEO = enumC4489i03;
        EnumC4489i0[] enumC4489i0Arr = {enumC4489i0, enumC4489i02, enumC4489i03};
        $VALUES = enumC4489i0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4489i0Arr);
        Companion = new C4486h0();
    }

    public EnumC4489i0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4489i0 valueOf(String str) {
        return (EnumC4489i0) Enum.valueOf(EnumC4489i0.class, str);
    }

    public static EnumC4489i0[] values() {
        return (EnumC4489i0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
