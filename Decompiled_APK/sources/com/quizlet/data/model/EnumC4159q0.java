package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.q0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4159q0 {
    public static final EnumC4159q0 a;
    public static final EnumC4159q0 b;
    public static final EnumC4159q0 c;
    public static final EnumC4159q0 d;
    public static final /* synthetic */ EnumC4159q0[] e;

    static {
        EnumC4159q0 enumC4159q0 = new EnumC4159q0("NONE", 0);
        a = enumC4159q0;
        EnumC4159q0 enumC4159q02 = new EnumC4159q0("TOO_LONG", 1);
        b = enumC4159q02;
        EnumC4159q0 enumC4159q03 = new EnumC4159q0("ALREADY_EXISTS", 2);
        c = enumC4159q03;
        EnumC4159q0 enumC4159q04 = new EnumC4159q0("MAX_TAGS_REACHED", 3);
        d = enumC4159q04;
        EnumC4159q0[] enumC4159q0Arr = {enumC4159q0, enumC4159q02, enumC4159q03, enumC4159q04};
        e = enumC4159q0Arr;
        AbstractC3328d.f(enumC4159q0Arr);
    }

    public static EnumC4159q0 valueOf(String str) {
        return (EnumC4159q0) Enum.valueOf(EnumC4159q0.class, str);
    }

    public static EnumC4159q0[] values() {
        return (EnumC4159q0[]) e.clone();
    }
}
