package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class z {
    public static final z a;
    public static final z b;
    public static final /* synthetic */ z[] c;

    static {
        z zVar = new z("LEARN_CHECKPOINT", 0);
        a = zVar;
        z zVar2 = new z("TEST_SUBMISSION", 1);
        b = zVar2;
        z[] zVarArr = {zVar, zVar2};
        c = zVarArr;
        AbstractC3328d.f(zVarArr);
    }

    public static z valueOf(String str) {
        return (z) Enum.valueOf(z.class, str);
    }

    public static z[] values() {
        return (z[]) c.clone();
    }
}
