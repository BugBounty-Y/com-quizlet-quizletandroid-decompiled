package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4473d {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4473d[] $VALUES;
    public static final EnumC4473d ACTIVITY;

    @NotNull
    public static final C4470c Companion;
    public static final EnumC4473d LIFETIME;
    public static final EnumC4473d STREAK;

    @NotNull
    private final String value;

    static {
        EnumC4473d enumC4473d = new EnumC4473d("ACTIVITY", 0, "Activity");
        ACTIVITY = enumC4473d;
        EnumC4473d enumC4473d2 = new EnumC4473d("LIFETIME", 1, "Lifetime");
        LIFETIME = enumC4473d2;
        EnumC4473d enumC4473d3 = new EnumC4473d("STREAK", 2, "Streak");
        STREAK = enumC4473d3;
        EnumC4473d[] enumC4473dArr = {enumC4473d, enumC4473d2, enumC4473d3};
        $VALUES = enumC4473dArr;
        $ENTRIES = AbstractC3328d.f(enumC4473dArr);
        Companion = new C4470c();
    }

    public EnumC4473d(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4473d valueOf(String str) {
        return (EnumC4473d) Enum.valueOf(EnumC4473d.class, str);
    }

    public static EnumC4473d[] values() {
        return (EnumC4473d[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
