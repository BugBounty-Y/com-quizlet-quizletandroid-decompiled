package com.airbnb.lottie.compose;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class l {
    public static final l a;
    public static final /* synthetic */ l[] b;

    static {
        l lVar = new l("Immediately", 0);
        a = lVar;
        l[] lVarArr = {lVar, new l("OnIterationFinish", 1)};
        b = lVarArr;
        AbstractC3328d.f(lVarArr);
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) b.clone();
    }
}
