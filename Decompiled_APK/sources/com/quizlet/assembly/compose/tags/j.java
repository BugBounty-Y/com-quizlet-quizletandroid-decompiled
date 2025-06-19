package com.quizlet.assembly.compose.tags;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final /* synthetic */ j[] c;

    static {
        j jVar = new j("Small", 0);
        j jVar2 = new j("Medium", 1);
        a = jVar2;
        j jVar3 = new j("Large", 2);
        b = jVar3;
        j[] jVarArr = {jVar, jVar2, jVar3};
        c = jVarArr;
        AbstractC3328d.f(jVarArr);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) c.clone();
    }
}
