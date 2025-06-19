package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4175w {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4175w[] $VALUES;
    public static final EnumC4175w COMPLETE;
    public static final EnumC4175w ERROR;
    public static final EnumC4175w MODERATION;
    public static final EnumC4175w PENDING;

    static {
        EnumC4175w enumC4175w = new EnumC4175w("PENDING", 0);
        PENDING = enumC4175w;
        EnumC4175w enumC4175w2 = new EnumC4175w("COMPLETE", 1);
        COMPLETE = enumC4175w2;
        EnumC4175w enumC4175w3 = new EnumC4175w("ERROR", 2);
        ERROR = enumC4175w3;
        EnumC4175w enumC4175w4 = new EnumC4175w("MODERATION", 3);
        MODERATION = enumC4175w4;
        EnumC4175w[] enumC4175wArr = {enumC4175w, enumC4175w2, enumC4175w3, enumC4175w4};
        $VALUES = enumC4175wArr;
        $ENTRIES = AbstractC3328d.f(enumC4175wArr);
    }

    public static kotlin.enums.a a() {
        return $ENTRIES;
    }

    public static EnumC4175w valueOf(String str) {
        return (EnumC4175w) Enum.valueOf(EnumC4175w.class, str);
    }

    public static EnumC4175w[] values() {
        return (EnumC4175w[]) $VALUES.clone();
    }
}
