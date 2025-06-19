package com.quizlet.ads.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class d {
    public static final d a;
    public static final d b;
    public static final d c;
    public static final d d;
    public static final d e;
    public static final d f;
    public static final /* synthetic */ d[] g;

    static {
        d dVar = new d("BANNER_AD", 0);
        a = dVar;
        d dVar2 = new d("NATIVE_AD", 1);
        b = dVar2;
        d dVar3 = new d("NATIVE_VIDEO_AD", 2);
        c = dVar3;
        d dVar4 = new d("OUTSTREAM_VIDEO_AD", 3);
        d = dVar4;
        d dVar5 = new d("VERTICAL_OUTSTREAM_VIDEO_AD_4_5", 4);
        e = dVar5;
        d dVar6 = new d("VERTICAL_OUTSTREAM_VIDEO_AD_9_16", 5);
        f = dVar6;
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4, dVar5, dVar6};
        g = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) g.clone();
    }
}
