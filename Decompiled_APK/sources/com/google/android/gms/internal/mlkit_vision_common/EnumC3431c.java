package com.google.android.gms.internal.mlkit_vision_common;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.mlkit_vision_common.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC3431c {
    public static final EnumC3431c a;
    public static final /* synthetic */ EnumC3431c[] b;

    static {
        EnumC3431c enumC3431c = new EnumC3431c("DEFAULT", 0);
        a = enumC3431c;
        b = new EnumC3431c[]{enumC3431c, new EnumC3431c("SIGNED", 1), new EnumC3431c("FIXED", 2)};
    }

    public static EnumC3431c[] values() {
        return (EnumC3431c[]) b.clone();
    }
}
