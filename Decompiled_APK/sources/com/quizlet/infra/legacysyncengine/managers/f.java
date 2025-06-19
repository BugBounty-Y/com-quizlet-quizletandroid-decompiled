package com.quizlet.infra.legacysyncengine.managers;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class f {
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;
    public final int a;

    static {
        f fVar = new f("MANUAL_ENTRY", 0, 1);
        b = fVar;
        f fVar2 = new f("QR_CODE", 1, 2);
        c = fVar2;
        f[] fVarArr = {fVar, fVar2};
        d = fVarArr;
        AbstractC3328d.f(fVarArr);
    }

    public f(String str, int i, int i2) {
        this.a = i2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }
}
