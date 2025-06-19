package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.u1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4171u1 {
    public static final EnumC4171u1 a;
    public static final EnumC4171u1 b;
    public static final EnumC4171u1 c;
    public static final /* synthetic */ EnumC4171u1[] d;

    static {
        EnumC4171u1 enumC4171u1 = new EnumC4171u1("Confirmed", 0);
        a = enumC4171u1;
        EnumC4171u1 enumC4171u12 = new EnumC4171u1("Unconfirmed", 1);
        b = enumC4171u12;
        EnumC4171u1 enumC4171u13 = new EnumC4171u1("ExceededLimit", 2);
        c = enumC4171u13;
        EnumC4171u1[] enumC4171u1Arr = {enumC4171u1, enumC4171u12, enumC4171u13};
        d = enumC4171u1Arr;
        AbstractC3328d.f(enumC4171u1Arr);
    }

    public static EnumC4171u1 valueOf(String str) {
        return (EnumC4171u1) Enum.valueOf(EnumC4171u1.class, str);
    }

    public static EnumC4171u1[] values() {
        return (EnumC4171u1[]) d.clone();
    }
}
