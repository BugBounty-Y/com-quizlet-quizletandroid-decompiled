package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4520t {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4520t[] $VALUES;
    public static final EnumC4520t CHECKPOINT;

    @NotNull
    public static final C4517s Companion;
    public static final EnumC4520t RESULTS;

    @NotNull
    private final String value;

    static {
        EnumC4520t enumC4520t = new EnumC4520t("CHECKPOINT", 0, "checkpoint");
        CHECKPOINT = enumC4520t;
        EnumC4520t enumC4520t2 = new EnumC4520t("RESULTS", 1, "results");
        RESULTS = enumC4520t2;
        EnumC4520t[] enumC4520tArr = {enumC4520t, enumC4520t2};
        $VALUES = enumC4520tArr;
        $ENTRIES = AbstractC3328d.f(enumC4520tArr);
        Companion = new C4517s();
    }

    public EnumC4520t(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4520t valueOf(String str) {
        return (EnumC4520t) Enum.valueOf(EnumC4520t.class, str);
    }

    public static EnumC4520t[] values() {
        return (EnumC4520t[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
