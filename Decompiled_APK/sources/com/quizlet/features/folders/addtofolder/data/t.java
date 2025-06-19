package com.quizlet.features.folders.addtofolder.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class t {
    public static final t a;
    public static final t b;
    public static final /* synthetic */ t[] c;

    static {
        t tVar = new t("OTHERS_ARE_STUDYING", 0);
        a = tVar;
        t tVar2 = new t("YOUR_LIBRARY", 1);
        b = tVar2;
        t[] tVarArr = {tVar, tVar2};
        c = tVarArr;
        AbstractC3328d.f(tVarArr);
    }

    public static t valueOf(String str) {
        return (t) Enum.valueOf(t.class, str);
    }

    public static t[] values() {
        return (t[]) c.clone();
    }
}
