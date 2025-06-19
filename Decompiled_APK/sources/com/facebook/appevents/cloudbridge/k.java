package com.facebook.appevents.cloudbridge;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class k {
    public static final k a;
    public static final k b;
    public static final k c;
    public static final /* synthetic */ k[] d;

    static {
        k kVar = new k("USER_DATA", 0);
        a = kVar;
        k kVar2 = new k("APP_DATA", 1);
        b = kVar2;
        k kVar3 = new k("CUSTOM_DATA", 2);
        c = kVar3;
        d = new k[]{kVar, kVar2, kVar3, new k("CUSTOM_EVENTS", 3)};
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) d.clone();
    }
}
