package com.quizlet.baserecyclerview.decoration;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class d {
    public static final d a;
    public static final /* synthetic */ d[] b;

    static {
        d dVar = new d("VERTICAL", 0);
        a = dVar;
        d[] dVarArr = {dVar, new d("HORIZONTAL", 1)};
        b = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) b.clone();
    }
}
