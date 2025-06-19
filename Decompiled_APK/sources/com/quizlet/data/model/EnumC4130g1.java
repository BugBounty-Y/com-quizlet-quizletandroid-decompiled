package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.g1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4130g1 {
    public static final EnumC4130g1 a;
    public static final EnumC4130g1 b;
    public static final EnumC4130g1 c;
    public static final /* synthetic */ EnumC4130g1[] d;

    static {
        EnumC4130g1 enumC4130g1 = new EnumC4130g1("FC_FLIP", 0);
        a = enumC4130g1;
        EnumC4130g1 enumC4130g12 = new EnumC4130g1("FC_SORTED", 1);
        b = enumC4130g12;
        EnumC4130g1 enumC4130g13 = new EnumC4130g1("LEARN", 2);
        c = enumC4130g13;
        EnumC4130g1[] enumC4130g1Arr = {enumC4130g1, enumC4130g12, enumC4130g13};
        d = enumC4130g1Arr;
        AbstractC3328d.f(enumC4130g1Arr);
    }

    public static EnumC4130g1 valueOf(String str) {
        return (EnumC4130g1) Enum.valueOf(EnumC4130g1.class, str);
    }

    public static EnumC4130g1[] values() {
        return (EnumC4130g1[]) d.clone();
    }
}
