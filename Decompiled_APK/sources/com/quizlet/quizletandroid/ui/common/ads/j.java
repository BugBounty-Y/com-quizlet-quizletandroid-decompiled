package com.quizlet.quizletandroid.ui.common.ads;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class j {
    public static final C4641h a;
    public static final j b;
    public static final j c;
    public static final /* synthetic */ j[] d;

    static {
        j jVar = new j("PORTRAIT", 0);
        b = jVar;
        j jVar2 = new j("LANDSCAPE", 1);
        c = jVar2;
        j[] jVarArr = {jVar, jVar2};
        d = jVarArr;
        AbstractC3328d.f(jVarArr);
        a = new C4641h(4);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) d.clone();
    }
}
