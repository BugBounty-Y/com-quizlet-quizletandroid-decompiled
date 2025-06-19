package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.v0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4173v0 {
    public static final C4170u0 b;
    public static final /* synthetic */ EnumC4173v0[] c;
    public final String a;

    static {
        EnumC4173v0[] enumC4173v0Arr = {new EnumC4173v0("ONE_DAY", 0, "Day"), new EnumC4173v0("ONE_WEEK", 1, "Week"), new EnumC4173v0("ONE_MONTH", 2, "Month")};
        c = enumC4173v0Arr;
        AbstractC3328d.f(enumC4173v0Arr);
        b = new C4170u0();
    }

    public EnumC4173v0(String str, int i, String str2) {
        this.a = str2;
    }

    public static EnumC4173v0 valueOf(String str) {
        return (EnumC4173v0) Enum.valueOf(EnumC4173v0.class, str);
    }

    public static EnumC4173v0[] values() {
        return (EnumC4173v0[]) c.clone();
    }
}
