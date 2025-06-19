package com.quizlet.features.achievements.achievement;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final e c;
    public static final /* synthetic */ e[] d;

    static {
        e eVar = new e("INTERNAL", 0);
        a = eVar;
        e eVar2 = new e("TOAST_TAPPED", 1);
        b = eVar2;
        e eVar3 = new e("TOAST_EXPLICITLY_DISMISSED", 2);
        c = eVar3;
        e[] eVarArr = {eVar, eVar2, eVar3};
        d = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) d.clone();
    }
}
