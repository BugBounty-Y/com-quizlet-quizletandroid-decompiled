package androidx.camera.core.impl;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.camera.core.impl.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0174m {
    public static final EnumC0174m a;
    public static final EnumC0174m b;
    public static final EnumC0174m c;
    public static final EnumC0174m d;
    public static final EnumC0174m e;
    public static final EnumC0174m f;
    public static final /* synthetic */ EnumC0174m[] g;

    static {
        EnumC0174m enumC0174m = new EnumC0174m("UNKNOWN", 0);
        a = enumC0174m;
        EnumC0174m enumC0174m2 = new EnumC0174m("INACTIVE", 1);
        b = enumC0174m2;
        EnumC0174m enumC0174m3 = new EnumC0174m("SEARCHING", 2);
        c = enumC0174m3;
        EnumC0174m enumC0174m4 = new EnumC0174m("FLASH_REQUIRED", 3);
        d = enumC0174m4;
        EnumC0174m enumC0174m5 = new EnumC0174m("CONVERGED", 4);
        e = enumC0174m5;
        EnumC0174m enumC0174m6 = new EnumC0174m("LOCKED", 5);
        f = enumC0174m6;
        g = new EnumC0174m[]{enumC0174m, enumC0174m2, enumC0174m3, enumC0174m4, enumC0174m5, enumC0174m6};
    }

    public static EnumC0174m valueOf(String str) {
        return (EnumC0174m) Enum.valueOf(EnumC0174m.class, str);
    }

    public static EnumC0174m[] values() {
        return (EnumC0174m[]) g.clone();
    }
}
