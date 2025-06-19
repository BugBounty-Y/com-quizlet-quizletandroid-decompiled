package com.quizlet.edgy.utils;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final /* synthetic */ e[] c;

    static {
        e eVar = new e("ALL_FIELDS", 0);
        a = eVar;
        e eVar2 = new e("AT_LEAST_ONE_FIELD", 1);
        b = eVar2;
        e[] eVarArr = {eVar, eVar2};
        c = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) c.clone();
    }
}
