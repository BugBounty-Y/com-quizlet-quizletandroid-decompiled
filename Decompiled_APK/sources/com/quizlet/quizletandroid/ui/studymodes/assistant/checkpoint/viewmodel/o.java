package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class o {
    public static final o a;
    public static final o b;
    public static final /* synthetic */ o[] c;

    static {
        o oVar = new o("NEVER_CORRECT", 0);
        a = oVar;
        o oVar2 = new o("CORRECT_ONCE", 1);
        b = oVar2;
        o[] oVarArr = {oVar, oVar2};
        c = oVarArr;
        AbstractC3328d.f(oVarArr);
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) c.clone();
    }
}
