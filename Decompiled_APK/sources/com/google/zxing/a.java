package com.google.zxing;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final a e;
    public static final a f;
    public static final a g;
    public static final a h;
    public static final a i;
    public static final a j;
    public static final a k;
    public static final a l;
    public static final /* synthetic */ a[] m;

    static {
        a aVar = new a("ERROR_CORRECTION", 0);
        a = aVar;
        a aVar2 = new a("CHARACTER_SET", 1);
        b = aVar2;
        a aVar3 = new a("DATA_MATRIX_SHAPE", 2);
        c = aVar3;
        a aVar4 = new a("MIN_SIZE", 3);
        d = aVar4;
        a aVar5 = new a("MAX_SIZE", 4);
        e = aVar5;
        a aVar6 = new a("MARGIN", 5);
        f = aVar6;
        a aVar7 = new a("PDF417_COMPACT", 6);
        g = aVar7;
        a aVar8 = new a("PDF417_COMPACTION", 7);
        h = aVar8;
        a aVar9 = new a("PDF417_DIMENSIONS", 8);
        i = aVar9;
        a aVar10 = new a("AZTEC_LAYERS", 9);
        j = aVar10;
        a aVar11 = new a("QR_VERSION", 10);
        k = aVar11;
        a aVar12 = new a("GS1_FORMAT", 11);
        l = aVar12;
        m = new a[]{aVar, aVar2, aVar3, aVar4, aVar5, aVar6, aVar7, aVar8, aVar9, aVar10, aVar11, aVar12};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) m.clone();
    }
}
