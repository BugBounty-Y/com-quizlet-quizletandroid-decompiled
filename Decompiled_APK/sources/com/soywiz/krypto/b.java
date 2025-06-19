package com.soywiz.krypto;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final b a;
    public static final b b;
    public static final /* synthetic */ b[] c;

    static {
        b bVar = new b("NoPadding", 0);
        a = bVar;
        b bVar2 = new b("PKCS7Padding", 1);
        b = bVar2;
        c = new b[]{bVar, bVar2, new b("ANSIX923Padding", 2), new b("ISO10126Padding", 3), new b("ZeroPadding", 4)};
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) c.clone();
    }
}
