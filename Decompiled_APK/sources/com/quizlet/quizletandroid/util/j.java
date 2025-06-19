package com.quizlet.quizletandroid.util;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final j c;
    public static final /* synthetic */ j[] d;

    static {
        j jVar = new j("PRIVATE", 0);
        a = jVar;
        j jVar2 = new j("PASSWORD", 1);
        b = jVar2;
        j jVar3 = new j("PUBLIC", 2);
        c = jVar3;
        j[] jVarArr = {jVar, jVar2, jVar3};
        d = jVarArr;
        AbstractC3328d.f(jVarArr);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) d.clone();
    }
}
