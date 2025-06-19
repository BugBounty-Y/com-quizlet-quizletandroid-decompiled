package com.google.android.datatransport.cct.internal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class y {
    public static final y a;
    public static final /* synthetic */ y[] b;

    /* JADX INFO: Fake field, exist only in values array */
    y EF0;

    static {
        y yVar = new y("UNKNOWN", 0);
        y yVar2 = new y("ANDROID_FIREBASE", 1);
        a = yVar2;
        b = new y[]{yVar, yVar2};
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) b.clone();
    }
}
