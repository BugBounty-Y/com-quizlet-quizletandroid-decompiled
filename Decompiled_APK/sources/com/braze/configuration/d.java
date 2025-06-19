package com.braze.configuration;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class d {
    public static final d b;
    public static final d c;
    public static final d d;
    public static final d e;
    public static final d f;
    public static final d g;
    public static final /* synthetic */ d[] h;
    public final String a;

    static {
        d dVar = new d("INTEGER", 0, "integer");
        b = dVar;
        d dVar2 = new d("COLOR", 1, "color");
        c = dVar2;
        d dVar3 = new d("BOOLEAN", 2, "bool");
        d = dVar3;
        d dVar4 = new d("STRING", 3, "string");
        e = dVar4;
        d dVar5 = new d("DRAWABLE_IDENTIFIER", 4, "drawable");
        f = dVar5;
        d dVar6 = new d("STRING_ARRAY", 5, "array");
        g = dVar6;
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4, dVar5, dVar6};
        h = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public d(String str, int i, String str2) {
        this.a = str2;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) h.clone();
    }
}
