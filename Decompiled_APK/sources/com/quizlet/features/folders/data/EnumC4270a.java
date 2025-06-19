package com.quizlet.features.folders.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.features.folders.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4270a {
    public static final EnumC4270a a;
    public static final EnumC4270a b;
    public static final EnumC4270a c;
    public static final /* synthetic */ EnumC4270a[] d;

    static {
        EnumC4270a enumC4270a = new EnumC4270a("Enabled", 0);
        a = enumC4270a;
        EnumC4270a enumC4270a2 = new EnumC4270a("Disabled", 1);
        b = enumC4270a2;
        EnumC4270a enumC4270a3 = new EnumC4270a("Hidden", 2);
        c = enumC4270a3;
        EnumC4270a[] enumC4270aArr = {enumC4270a, enumC4270a2, enumC4270a3};
        d = enumC4270aArr;
        AbstractC3328d.f(enumC4270aArr);
    }

    public static EnumC4270a valueOf(String str) {
        return (EnumC4270a) Enum.valueOf(EnumC4270a.class, str);
    }

    public static EnumC4270a[] values() {
        return (EnumC4270a[]) d.clone();
    }
}
