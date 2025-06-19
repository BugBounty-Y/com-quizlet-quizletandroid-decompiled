package com.quizlet.scandocument.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.scandocument.model.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4781a {
    public static final EnumC4781a a;
    public static final EnumC4781a b;
    public static final /* synthetic */ EnumC4781a[] c;

    static {
        EnumC4781a enumC4781a = new EnumC4781a("OCR", 0);
        a = enumC4781a;
        EnumC4781a enumC4781a2 = new EnumC4781a("KEYBOARD", 1);
        b = enumC4781a2;
        EnumC4781a[] enumC4781aArr = {enumC4781a, enumC4781a2};
        c = enumC4781aArr;
        AbstractC3328d.f(enumC4781aArr);
    }

    public static EnumC4781a valueOf(String str) {
        return (EnumC4781a) Enum.valueOf(EnumC4781a.class, str);
    }

    public static EnumC4781a[] values() {
        return (EnumC4781a[]) c.clone();
    }
}
