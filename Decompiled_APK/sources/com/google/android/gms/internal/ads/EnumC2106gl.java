package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.ads.gl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC2106gl {
    public static final EnumC2106gl a;
    public static final EnumC2106gl b;
    public static final EnumC2106gl c;
    public static final /* synthetic */ EnumC2106gl[] d;

    static {
        EnumC2106gl enumC2106gl = new EnumC2106gl("AD_REQUESTED", 0);
        a = enumC2106gl;
        EnumC2106gl enumC2106gl2 = new EnumC2106gl("AD_LOADED", 1);
        b = enumC2106gl2;
        EnumC2106gl enumC2106gl3 = new EnumC2106gl("AD_LOAD_FAILED", 2);
        c = enumC2106gl3;
        d = new EnumC2106gl[]{enumC2106gl, enumC2106gl2, enumC2106gl3};
    }

    public static EnumC2106gl[] values() {
        return (EnumC2106gl[]) d.clone();
    }
}
