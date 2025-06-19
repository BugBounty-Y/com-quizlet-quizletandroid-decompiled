package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4526v {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4526v[] $VALUES;
    public static final EnumC4526v ADMIN;
    public static final EnumC4526v APPLICANT;
    public static final EnumC4526v CREATOR;

    @NotNull
    public static final C4523u Companion;
    public static final EnumC4526v MEMBER;
    public static final EnumC4526v REJECTED;
    public static final EnumC4526v REMOVED;
    public static final EnumC4526v UNINVOLVED;
    private final int value;

    static {
        EnumC4526v enumC4526v = new EnumC4526v("UNINVOLVED", 0, -3);
        UNINVOLVED = enumC4526v;
        EnumC4526v enumC4526v2 = new EnumC4526v("REMOVED", 1, -2);
        REMOVED = enumC4526v2;
        EnumC4526v enumC4526v3 = new EnumC4526v("REJECTED", 2, -1);
        REJECTED = enumC4526v3;
        EnumC4526v enumC4526v4 = new EnumC4526v("APPLICANT", 3, 0);
        APPLICANT = enumC4526v4;
        EnumC4526v enumC4526v5 = new EnumC4526v("MEMBER", 4, 1);
        MEMBER = enumC4526v5;
        EnumC4526v enumC4526v6 = new EnumC4526v("ADMIN", 5, 3);
        ADMIN = enumC4526v6;
        EnumC4526v enumC4526v7 = new EnumC4526v("CREATOR", 6, 4);
        CREATOR = enumC4526v7;
        EnumC4526v[] enumC4526vArr = {enumC4526v, enumC4526v2, enumC4526v3, enumC4526v4, enumC4526v5, enumC4526v6, enumC4526v7};
        $VALUES = enumC4526vArr;
        $ENTRIES = AbstractC3328d.f(enumC4526vArr);
        Companion = new C4523u();
    }

    public EnumC4526v(String str, int i, int i2) {
        this.value = i2;
    }

    public static EnumC4526v valueOf(String str) {
        return (EnumC4526v) Enum.valueOf(EnumC4526v.class, str);
    }

    public static EnumC4526v[] values() {
        return (EnumC4526v[]) $VALUES.clone();
    }

    public final int a() {
        return this.value;
    }
}
