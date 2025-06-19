package com.quizlet.ui.models.search;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d {
    public static final d a;
    public static final d b;
    public static final d c;
    public static final d d;
    public static final /* synthetic */ d[] e;

    static {
        d dVar = new d("NOW", 0);
        a = dVar;
        d dVar2 = new d("TODAY", 1);
        b = dVar2;
        d dVar3 = new d("DAYS", 2);
        c = dVar3;
        d dVar4 = new d("RECENTLY", 3);
        d = dVar4;
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4};
        e = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) e.clone();
    }
}
