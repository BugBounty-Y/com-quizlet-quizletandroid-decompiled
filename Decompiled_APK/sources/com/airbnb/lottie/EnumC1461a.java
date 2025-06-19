package com.airbnb.lottie;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.airbnb.lottie.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1461a {
    public static final EnumC1461a a;
    public static final EnumC1461a b;
    public static final /* synthetic */ EnumC1461a[] c;

    static {
        EnumC1461a enumC1461a = new EnumC1461a("AUTOMATIC", 0);
        a = enumC1461a;
        EnumC1461a enumC1461a2 = new EnumC1461a("ENABLED", 1);
        b = enumC1461a2;
        c = new EnumC1461a[]{enumC1461a, enumC1461a2, new EnumC1461a("DISABLED", 2)};
    }

    public static EnumC1461a valueOf(String str) {
        return (EnumC1461a) Enum.valueOf(EnumC1461a.class, str);
    }

    public static EnumC1461a[] values() {
        return (EnumC1461a[]) c.clone();
    }
}
