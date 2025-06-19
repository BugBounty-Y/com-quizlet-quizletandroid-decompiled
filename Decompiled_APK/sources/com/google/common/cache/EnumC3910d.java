package com.google.common.cache;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.common.cache.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC3910d {
    public static final EnumC3910d a;
    public static final /* synthetic */ EnumC3910d[] b;

    static {
        EnumC3910d enumC3910d = new EnumC3910d("INSTANCE", 0);
        a = enumC3910d;
        b = new EnumC3910d[]{enumC3910d};
    }

    public static EnumC3910d valueOf(String str) {
        return (EnumC3910d) Enum.valueOf(EnumC3910d.class, str);
    }

    public static EnumC3910d[] values() {
        return (EnumC3910d[]) b.clone();
    }
}
