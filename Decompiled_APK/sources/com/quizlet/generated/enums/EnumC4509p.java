package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4509p {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4509p[] $VALUES;

    @NotNull
    public static final C4506o Companion;
    public static final EnumC4509p FOLDER;
    public static final EnumC4509p PREP_PACK;
    public static final EnumC4509p SET;

    @NotNull
    private final String value;

    static {
        EnumC4509p enumC4509p = new EnumC4509p("SET", 0, "set");
        SET = enumC4509p;
        EnumC4509p enumC4509p2 = new EnumC4509p("FOLDER", 1, "folder");
        FOLDER = enumC4509p2;
        EnumC4509p enumC4509p3 = new EnumC4509p("PREP_PACK", 2, "prep_pack");
        PREP_PACK = enumC4509p3;
        EnumC4509p[] enumC4509pArr = {enumC4509p, enumC4509p2, enumC4509p3};
        $VALUES = enumC4509pArr;
        $ENTRIES = AbstractC3328d.f(enumC4509pArr);
        Companion = new C4506o();
    }

    public EnumC4509p(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4509p valueOf(String str) {
        return (EnumC4509p) Enum.valueOf(EnumC4509p.class, str);
    }

    public static EnumC4509p[] values() {
        return (EnumC4509p[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
