package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.w0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4529w0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4529w0[] $VALUES;
    public static final EnumC4529w0 COMPLETE;

    @NotNull
    public static final C4527v0 Companion;
    public static final EnumC4529w0 DELETED;
    public static final EnumC4529w0 ERROR;
    public static final EnumC4529w0 INELIGIBLE;
    public static final EnumC4529w0 MODERATION;
    public static final EnumC4529w0 PENDING;
    private final int value;

    static {
        EnumC4529w0 enumC4529w0 = new EnumC4529w0("PENDING", 0, 0);
        PENDING = enumC4529w0;
        EnumC4529w0 enumC4529w02 = new EnumC4529w0("COMPLETE", 1, 1);
        COMPLETE = enumC4529w02;
        EnumC4529w0 enumC4529w03 = new EnumC4529w0("ERROR", 2, 2);
        ERROR = enumC4529w03;
        EnumC4529w0 enumC4529w04 = new EnumC4529w0("INELIGIBLE", 3, 3);
        INELIGIBLE = enumC4529w04;
        EnumC4529w0 enumC4529w05 = new EnumC4529w0("MODERATION", 4, 4);
        MODERATION = enumC4529w05;
        EnumC4529w0 enumC4529w06 = new EnumC4529w0("DELETED", 5, 5);
        DELETED = enumC4529w06;
        EnumC4529w0[] enumC4529w0Arr = {enumC4529w0, enumC4529w02, enumC4529w03, enumC4529w04, enumC4529w05, enumC4529w06};
        $VALUES = enumC4529w0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4529w0Arr);
        Companion = new C4527v0();
    }

    public EnumC4529w0(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4529w0 valueOf(String str) {
        return (EnumC4529w0) Enum.valueOf(EnumC4529w0.class, str);
    }

    public static EnumC4529w0[] values() {
        return (EnumC4529w0[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
