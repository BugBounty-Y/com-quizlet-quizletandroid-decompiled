package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.ads.ol, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC2450ol {
    public static final EnumC2450ol a;
    public static final EnumC2450ol b;
    public static final EnumC2450ol c;
    public static final EnumC2450ol d;
    public static final /* synthetic */ EnumC2450ol[] e;

    static {
        EnumC2450ol enumC2450ol = new EnumC2450ol("UNKNOWN", 0);
        a = enumC2450ol;
        EnumC2450ol enumC2450ol2 = new EnumC2450ol("API", 1);
        b = enumC2450ol2;
        EnumC2450ol enumC2450ol3 = new EnumC2450ol("GESTURE", 2);
        c = enumC2450ol3;
        EnumC2450ol enumC2450ol4 = new EnumC2450ol("DEBUG_MENU", 3);
        d = enumC2450ol4;
        e = new EnumC2450ol[]{enumC2450ol, enumC2450ol2, enumC2450ol3, enumC2450ol4};
    }

    public static EnumC2450ol[] values() {
        return (EnumC2450ol[]) e.clone();
    }
}
