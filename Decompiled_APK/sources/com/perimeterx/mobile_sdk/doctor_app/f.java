package com.perimeterx.mobile_sdk.doctor_app;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class f {
    public static final com.quizlet.shared.usecase.folderstudymaterials.a a;
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;

    static {
        f fVar = new f("BOT_DEFENDER", 0);
        b = fVar;
        f fVar2 = new f("ACCOUNT_DEFENDER", 1);
        c = fVar2;
        f[] fVarArr = {fVar, fVar2};
        d = fVarArr;
        AbstractC3328d.f(fVarArr);
        a = new com.quizlet.shared.usecase.folderstudymaterials.a(22);
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }
}
