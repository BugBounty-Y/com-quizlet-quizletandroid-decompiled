package com.quizlet.quizletandroid.util.kext;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final /* synthetic */ a[] a;

    static {
        a[] aVarArr = {new a("FIRST_CARD", 0), new a("LAST_CARD", 1), new a("NORMAL_CARD", 2)};
        a = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) a.clone();
    }
}
