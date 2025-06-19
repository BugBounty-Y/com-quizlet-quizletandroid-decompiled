package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.ads.ll, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC2321ll {
    public static final EnumC2321ll a;
    public static final EnumC2321ll b;
    public static final EnumC2321ll c;
    public static final /* synthetic */ EnumC2321ll[] d;

    static {
        EnumC2321ll enumC2321ll = new EnumC2321ll("NONE", 0);
        a = enumC2321ll;
        EnumC2321ll enumC2321ll2 = new EnumC2321ll("SHAKE", 1);
        b = enumC2321ll2;
        EnumC2321ll enumC2321ll3 = new EnumC2321ll("FLICK", 2);
        c = enumC2321ll3;
        d = new EnumC2321ll[]{enumC2321ll, enumC2321ll2, enumC2321ll3};
    }

    public static EnumC2321ll[] values() {
        return (EnumC2321ll[]) d.clone();
    }
}
