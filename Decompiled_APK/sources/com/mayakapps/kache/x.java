package com.mayakapps.kache;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class x {
    public static final x a;
    public static final x b;
    public static final x c;
    public static final x d;
    public static final /* synthetic */ x[] e;

    static {
        x xVar = new x("LRU", 0);
        a = xVar;
        x xVar2 = new x("MRU", 1);
        b = xVar2;
        x xVar3 = new x("FIFO", 2);
        c = xVar3;
        x xVar4 = new x("FILO", 3);
        d = xVar4;
        x[] xVarArr = {xVar, xVar2, xVar3, xVar4};
        e = xVarArr;
        AbstractC3328d.f(xVarArr);
    }

    public static x valueOf(String str) {
        return (x) Enum.valueOf(x.class, str);
    }

    public static x[] values() {
        return (x[]) e.clone();
    }
}
