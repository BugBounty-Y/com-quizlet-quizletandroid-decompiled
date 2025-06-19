package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class m {
    public static final m a;
    public static final /* synthetic */ m[] b;
    public static final /* synthetic */ kotlin.enums.b c;

    static {
        m mVar = new m("Original", 0);
        a = mVar;
        m[] mVarArr = {mVar, new m("Alphabetically", 1)};
        b = mVarArr;
        c = AbstractC3328d.f(mVarArr);
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) b.clone();
    }
}
