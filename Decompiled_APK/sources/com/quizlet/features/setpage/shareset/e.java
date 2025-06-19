package com.quizlet.features.setpage.shareset;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class e {
    public static final /* synthetic */ e[] a;

    static {
        e[] eVarArr = {new e("THUMBS_UP", 0), new e("SUNGLASSES", 1)};
        a = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) a.clone();
    }
}
