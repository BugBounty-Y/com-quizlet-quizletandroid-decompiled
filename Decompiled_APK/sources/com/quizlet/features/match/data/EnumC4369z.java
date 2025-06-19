package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.features.match.data.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4369z {
    public static final EnumC4369z a;
    public static final EnumC4369z b;
    public static final /* synthetic */ EnumC4369z[] c;

    static {
        EnumC4369z enumC4369z = new EnumC4369z("STANDARD", 0);
        a = enumC4369z;
        EnumC4369z enumC4369z2 = new EnumC4369z("DIAGRAM", 1);
        b = enumC4369z2;
        EnumC4369z[] enumC4369zArr = {enumC4369z, enumC4369z2};
        c = enumC4369zArr;
        AbstractC3328d.f(enumC4369zArr);
    }

    public static EnumC4369z valueOf(String str) {
        return (EnumC4369z) Enum.valueOf(EnumC4369z.class, str);
    }

    public static EnumC4369z[] values() {
        return (EnumC4369z[]) c.clone();
    }
}
