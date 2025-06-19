package com.quizlet.shared.httpclient;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d {
    public static final d a;
    public static final d b;
    public static final d c;
    public static final /* synthetic */ d[] d;

    static {
        d dVar = new d("GET", 0);
        a = dVar;
        d dVar2 = new d("POST", 1);
        b = dVar2;
        d dVar3 = new d("PUT", 2);
        d dVar4 = new d("DELETE", 3);
        c = dVar4;
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4, new d("PATCH", 4)};
        d = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) d.clone();
    }
}
