package com.quizlet.features.settings.data.models;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class f {
    public static final f a;
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;

    static {
        f fVar = new f("Google", 0);
        a = fVar;
        f fVar2 = new f("Password", 1);
        b = fVar2;
        f fVar3 = new f("Facebook", 2);
        c = fVar3;
        f[] fVarArr = {fVar, fVar2, fVar3};
        d = fVarArr;
        AbstractC3328d.f(fVarArr);
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }
}
