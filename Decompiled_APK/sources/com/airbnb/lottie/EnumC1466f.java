package com.airbnb.lottie;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.airbnb.lottie.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1466f {
    public static final EnumC1466f a;
    public static final EnumC1466f b;
    public static final EnumC1466f c;
    public static final EnumC1466f d;
    public static final EnumC1466f e;
    public static final EnumC1466f f;
    public static final /* synthetic */ EnumC1466f[] g;

    static {
        EnumC1466f enumC1466f = new EnumC1466f("SET_ANIMATION", 0);
        a = enumC1466f;
        EnumC1466f enumC1466f2 = new EnumC1466f("SET_PROGRESS", 1);
        b = enumC1466f2;
        EnumC1466f enumC1466f3 = new EnumC1466f("SET_REPEAT_MODE", 2);
        c = enumC1466f3;
        EnumC1466f enumC1466f4 = new EnumC1466f("SET_REPEAT_COUNT", 3);
        d = enumC1466f4;
        EnumC1466f enumC1466f5 = new EnumC1466f("SET_IMAGE_ASSETS", 4);
        e = enumC1466f5;
        EnumC1466f enumC1466f6 = new EnumC1466f("PLAY_OPTION", 5);
        f = enumC1466f6;
        g = new EnumC1466f[]{enumC1466f, enumC1466f2, enumC1466f3, enumC1466f4, enumC1466f5, enumC1466f6};
    }

    public static EnumC1466f valueOf(String str) {
        return (EnumC1466f) Enum.valueOf(EnumC1466f.class, str);
    }

    public static EnumC1466f[] values() {
        return (EnumC1466f[]) g.clone();
    }
}
