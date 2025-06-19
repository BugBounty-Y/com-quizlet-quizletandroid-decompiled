package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class YA {
    public static final YA a;
    public static final YA b;
    public static final YA c;
    public static final YA d;
    public static final YA e;
    public static final YA f;
    public static final YA g;
    public static final YA h;
    public static final YA i;
    public static final YA j;
    public static final /* synthetic */ YA[] k;

    static {
        YA ya = new YA("VOID", 0);
        a = ya;
        YA ya2 = new YA("INT", 1);
        b = ya2;
        YA ya3 = new YA("LONG", 2);
        c = ya3;
        YA ya4 = new YA("FLOAT", 3);
        d = ya4;
        YA ya5 = new YA("DOUBLE", 4);
        e = ya5;
        YA ya6 = new YA("BOOLEAN", 5);
        f = ya6;
        YA ya7 = new YA("STRING", 6);
        g = ya7;
        C2905zA c2905zA = BA.b;
        YA ya8 = new YA("BYTE_STRING", 7);
        h = ya8;
        YA ya9 = new YA("ENUM", 8);
        i = ya9;
        YA ya10 = new YA("MESSAGE", 9);
        j = ya10;
        k = new YA[]{ya, ya2, ya3, ya4, ya5, ya6, ya7, ya8, ya9, ya10};
    }

    public static YA[] values() {
        return (YA[]) k.clone();
    }
}
