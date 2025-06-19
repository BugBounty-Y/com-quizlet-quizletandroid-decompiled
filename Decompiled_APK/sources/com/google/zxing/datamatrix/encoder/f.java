package com.google.zxing.datamatrix.encoder;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class f {
    public static final f a;
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;

    static {
        f fVar = new f("FORCE_NONE", 0);
        a = fVar;
        f fVar2 = new f("FORCE_SQUARE", 1);
        b = fVar2;
        f fVar3 = new f("FORCE_RECTANGLE", 2);
        c = fVar3;
        d = new f[]{fVar, fVar2, fVar3};
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }
}
