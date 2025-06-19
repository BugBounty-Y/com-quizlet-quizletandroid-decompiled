package com.facebook.login;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.facebook.login.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1564a {
    public static final EnumC1564a a;
    public static final EnumC1564a b;
    public static final /* synthetic */ EnumC1564a[] c;

    static {
        EnumC1564a enumC1564a = new EnumC1564a("S256", 0);
        a = enumC1564a;
        EnumC1564a enumC1564a2 = new EnumC1564a("PLAIN", 1);
        b = enumC1564a2;
        c = new EnumC1564a[]{enumC1564a, enumC1564a2};
    }

    public static EnumC1564a valueOf(String str) {
        return (EnumC1564a) Enum.valueOf(EnumC1564a.class, str);
    }

    public static EnumC1564a[] values() {
        return (EnumC1564a[]) c.clone();
    }
}
