package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class f {
    public static final f a;
    public static final f b;
    public static final /* synthetic */ f[] c;

    static {
        f fVar = new f("NONE", 0);
        a = fVar;
        f fVar2 = new f("LOCKED", 1);
        b = fVar2;
        f[] fVarArr = {fVar, fVar2};
        c = fVarArr;
        AbstractC3328d.f(fVarArr);
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) c.clone();
    }
}
