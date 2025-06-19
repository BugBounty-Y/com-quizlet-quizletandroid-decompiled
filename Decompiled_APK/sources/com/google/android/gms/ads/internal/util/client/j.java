package com.google.android.gms.ads.internal.util.client;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final j c;
    public static final j d;
    public static final /* synthetic */ j[] e;

    static {
        j jVar = new j("SUCCESS", 0);
        a = jVar;
        j jVar2 = new j("PERMANENT_FAILURE", 1);
        b = jVar2;
        j jVar3 = new j("RETRIABLE_FAILURE", 2);
        c = jVar3;
        j jVar4 = new j("BUFFERED", 3);
        d = jVar4;
        e = new j[]{jVar, jVar2, jVar3, jVar4};
    }

    public static j[] values() {
        return (j[]) e.clone();
    }
}
