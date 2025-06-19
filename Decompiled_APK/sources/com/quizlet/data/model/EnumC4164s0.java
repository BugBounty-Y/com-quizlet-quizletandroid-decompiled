package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.s0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4164s0 {
    public static final EnumC4164s0 a;
    public static final EnumC4164s0 b;
    public static final EnumC4164s0 c;
    public static final EnumC4164s0 d;
    public static final EnumC4164s0 e;
    public static final EnumC4164s0 f;
    public static final /* synthetic */ EnumC4164s0[] g;
    public static final /* synthetic */ kotlin.enums.b h;

    static {
        EnumC4164s0 enumC4164s0 = new EnumC4164s0("STUDY_SETS", 0);
        a = enumC4164s0;
        EnumC4164s0 enumC4164s02 = new EnumC4164s0("NOTES", 1);
        b = enumC4164s02;
        EnumC4164s0 enumC4164s03 = new EnumC4164s0("FOLDERS", 2);
        c = enumC4164s03;
        EnumC4164s0 enumC4164s04 = new EnumC4164s0("CLASSES", 3);
        d = enumC4164s04;
        EnumC4164s0 enumC4164s05 = new EnumC4164s0("PRACTICE_TEST", 4);
        e = enumC4164s05;
        EnumC4164s0 enumC4164s06 = new EnumC4164s0("YOUR_SOLUTIONS", 5);
        f = enumC4164s06;
        EnumC4164s0[] enumC4164s0Arr = {enumC4164s0, enumC4164s02, enumC4164s03, enumC4164s04, enumC4164s05, enumC4164s06};
        g = enumC4164s0Arr;
        h = AbstractC3328d.f(enumC4164s0Arr);
    }

    public static EnumC4164s0 valueOf(String str) {
        return (EnumC4164s0) Enum.valueOf(EnumC4164s0.class, str);
    }

    public static EnumC4164s0[] values() {
        return (EnumC4164s0[]) g.clone();
    }
}
