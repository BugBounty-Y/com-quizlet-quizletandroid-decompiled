package org.wordpress.aztec.handlers;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final a e;
    public static final /* synthetic */ a[] f;

    static {
        a aVar = new a("START_OF_BLOCK", 0);
        a = aVar;
        a aVar2 = new a("EMPTY_LINE_AT_BLOCK_END", 1);
        b = aVar2;
        a aVar3 = new a("EMPTY_LINE_AT_EMPTY_BODY", 2);
        c = aVar3;
        a aVar4 = new a("BUFFER_END", 3);
        d = aVar4;
        a aVar5 = new a("BODY", 4);
        e = aVar5;
        a[] aVarArr = {aVar, aVar2, aVar3, aVar4, aVar5};
        f = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) f.clone();
    }
}
