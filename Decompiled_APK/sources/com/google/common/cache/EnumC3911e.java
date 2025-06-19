package com.google.common.cache;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.common.cache.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC3911e {
    public static final EnumC3911e a;
    public static final /* synthetic */ EnumC3911e[] b;

    static {
        EnumC3911e enumC3911e = new EnumC3911e("INSTANCE", 0);
        a = enumC3911e;
        b = new EnumC3911e[]{enumC3911e};
    }

    public static EnumC3911e valueOf(String str) {
        return (EnumC3911e) Enum.valueOf(EnumC3911e.class, str);
    }

    public static EnumC3911e[] values() {
        return (EnumC3911e[]) b.clone();
    }
}
