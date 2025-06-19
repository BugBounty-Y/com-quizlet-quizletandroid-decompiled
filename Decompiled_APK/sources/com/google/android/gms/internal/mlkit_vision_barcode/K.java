package com.google.android.gms.internal.mlkit_vision_barcode;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class K {
    public static final K a;
    public static final /* synthetic */ K[] b;

    static {
        K k = new K("DEFAULT", 0);
        a = k;
        b = new K[]{k, new K("SIGNED", 1), new K("FIXED", 2)};
    }

    public static K[] values() {
        return (K[]) b.clone();
    }
}
