package org.wordpress.aztec.spans;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: org.wordpress.aztec.spans.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC5157e {
    public static final EnumC5157e c;
    public static final EnumC5157e d;
    public static final EnumC5157e e;
    public static final EnumC5157e f;
    public static final EnumC5157e g;
    public static final EnumC5157e h;
    public static final /* synthetic */ EnumC5157e[] i;
    public final float a;
    public final String b;

    static {
        EnumC5157e enumC5157e = new EnumC5157e("H1", 0, 1.73f, "h1");
        c = enumC5157e;
        EnumC5157e enumC5157e2 = new EnumC5157e("H2", 1, 1.32f, "h2");
        d = enumC5157e2;
        EnumC5157e enumC5157e3 = new EnumC5157e("H3", 2, 1.02f, "h3");
        e = enumC5157e3;
        EnumC5157e enumC5157e4 = new EnumC5157e("H4", 3, 0.87f, "h4");
        f = enumC5157e4;
        EnumC5157e enumC5157e5 = new EnumC5157e("H5", 4, 0.72f, "h5");
        g = enumC5157e5;
        EnumC5157e enumC5157e6 = new EnumC5157e("H6", 5, 0.6f, "h6");
        h = enumC5157e6;
        EnumC5157e[] enumC5157eArr = {enumC5157e, enumC5157e2, enumC5157e3, enumC5157e4, enumC5157e5, enumC5157e6};
        i = enumC5157eArr;
        AbstractC3328d.f(enumC5157eArr);
    }

    public EnumC5157e(String str, int i2, float f2, String str2) {
        this.a = f2;
        this.b = str2;
    }

    public static EnumC5157e valueOf(String str) {
        return (EnumC5157e) Enum.valueOf(EnumC5157e.class, str);
    }

    public static EnumC5157e[] values() {
        return (EnumC5157e[]) i.clone();
    }
}
