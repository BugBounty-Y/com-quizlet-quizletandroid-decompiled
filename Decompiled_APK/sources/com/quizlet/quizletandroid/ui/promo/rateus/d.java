package com.quizlet.quizletandroid.ui.promo.rateus;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d {
    public static final d a;
    public static final d b;
    public static final /* synthetic */ d[] c;

    static {
        d dVar = new d("INITIAL", 0);
        a = dVar;
        d dVar2 = new d("RATE_US", 1);
        b = dVar2;
        d[] dVarArr = {dVar, dVar2};
        c = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) c.clone();
    }
}
