package com.onetrust.otpublishers.headless.UI.DataModels;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class k {
    public static final k a;
    public static final k b;
    public static final k c;
    public static final k d;
    public static final /* synthetic */ k[] e;

    static {
        k kVar = new k("Grant", 0);
        a = kVar;
        k kVar2 = new k("Deny", 1);
        b = kVar2;
        k kVar3 = new k("NoToggle", 2);
        c = kVar3;
        k kVar4 = new k("AlwaysActive", 3);
        d = kVar4;
        e = new k[]{kVar, kVar2, kVar3, kVar4};
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) e.clone();
    }
}
