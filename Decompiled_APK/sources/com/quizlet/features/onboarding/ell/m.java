package com.quizlet.features.onboarding.ell;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class m {
    public static final /* synthetic */ m[] a;
    public static final /* synthetic */ kotlin.enums.b b;

    static {
        m[] mVarArr = {new m("IELTS", 0), new m("TOEFL", 1), new m("TOEIC", 2)};
        a = mVarArr;
        b = AbstractC3328d.f(mVarArr);
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) a.clone();
    }
}
