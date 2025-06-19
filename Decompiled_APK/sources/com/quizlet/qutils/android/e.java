package com.quizlet.qutils.android;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class e {
    public static final com.quizlet.quizletandroid.ui.common.images.capture.b a;
    public static final e b;
    public static final e c;
    public static final /* synthetic */ e[] d;

    static {
        e eVar = new e("PORTRAIT", 0);
        b = eVar;
        e eVar2 = new e("LANDSCAPE", 1);
        c = eVar2;
        e[] eVarArr = {eVar, eVar2};
        d = eVarArr;
        AbstractC3328d.f(eVarArr);
        a = new com.quizlet.quizletandroid.ui.common.images.capture.b(1);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) d.clone();
    }
}
