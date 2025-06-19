package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.ads.uq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC2712uq {
    public static final EnumC2712uq a;
    public static final EnumC2712uq b;
    public static final EnumC2712uq c;
    public static final /* synthetic */ EnumC2712uq[] d;

    static {
        EnumC2712uq enumC2712uq = new EnumC2712uq("Rewarded", 0);
        a = enumC2712uq;
        EnumC2712uq enumC2712uq2 = new EnumC2712uq("Interstitial", 1);
        b = enumC2712uq2;
        EnumC2712uq enumC2712uq3 = new EnumC2712uq("AppOpen", 2);
        c = enumC2712uq3;
        d = new EnumC2712uq[]{enumC2712uq, enumC2712uq2, enumC2712uq3};
    }

    public static EnumC2712uq[] values() {
        return (EnumC2712uq[]) d.clone();
    }
}
