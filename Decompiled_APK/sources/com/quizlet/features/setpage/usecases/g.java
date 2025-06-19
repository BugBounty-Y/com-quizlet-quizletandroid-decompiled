package com.quizlet.features.setpage.usecases;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class g {
    public static final g a;
    public static final g b;
    public static final g c;
    public static final /* synthetic */ g[] d;

    static {
        g gVar = new g("HAS_PERMISSION", 0);
        a = gVar;
        g gVar2 = new g("NEED_PASSWORD", 1);
        b = gVar2;
        g gVar3 = new g("NO_PERMISSION", 2);
        c = gVar3;
        g[] gVarArr = {gVar, gVar2, gVar3};
        d = gVarArr;
        AbstractC3328d.f(gVarArr);
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) d.clone();
    }
}
