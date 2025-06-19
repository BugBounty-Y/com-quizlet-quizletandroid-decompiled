package org.wordpress.aztec;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: org.wordpress.aztec.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC5145a {
    public static final EnumC5145a a;
    public static final EnumC5145a b;
    public static final /* synthetic */ EnumC5145a[] c;

    static {
        EnumC5145a enumC5145a = new EnumC5145a("SPAN_LEVEL", 0);
        a = enumC5145a;
        EnumC5145a enumC5145a2 = new EnumC5145a("VIEW_LEVEL", 1);
        b = enumC5145a2;
        EnumC5145a[] enumC5145aArr = {enumC5145a, enumC5145a2};
        c = enumC5145aArr;
        AbstractC3328d.f(enumC5145aArr);
    }

    public static EnumC5145a valueOf(String str) {
        return (EnumC5145a) Enum.valueOf(EnumC5145a.class, str);
    }

    public static EnumC5145a[] values() {
        return (EnumC5145a[]) c.clone();
    }
}
