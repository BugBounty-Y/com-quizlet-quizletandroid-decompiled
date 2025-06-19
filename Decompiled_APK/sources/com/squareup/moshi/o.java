package com.squareup.moshi;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class o {
    public static final o a;
    public static final o b;
    public static final o c;
    public static final o d;
    public static final o e;
    public static final o f;
    public static final o g;
    public static final o h;
    public static final o i;
    public static final o j;
    public static final /* synthetic */ o[] k;

    static {
        o oVar = new o("BEGIN_ARRAY", 0);
        a = oVar;
        o oVar2 = new o("END_ARRAY", 1);
        b = oVar2;
        o oVar3 = new o("BEGIN_OBJECT", 2);
        c = oVar3;
        o oVar4 = new o("END_OBJECT", 3);
        d = oVar4;
        o oVar5 = new o("NAME", 4);
        e = oVar5;
        o oVar6 = new o("STRING", 5);
        f = oVar6;
        o oVar7 = new o("NUMBER", 6);
        g = oVar7;
        o oVar8 = new o("BOOLEAN", 7);
        h = oVar8;
        o oVar9 = new o("NULL", 8);
        i = oVar9;
        o oVar10 = new o("END_DOCUMENT", 9);
        j = oVar10;
        k = new o[]{oVar, oVar2, oVar3, oVar4, oVar5, oVar6, oVar7, oVar8, oVar9, oVar10};
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) k.clone();
    }
}
