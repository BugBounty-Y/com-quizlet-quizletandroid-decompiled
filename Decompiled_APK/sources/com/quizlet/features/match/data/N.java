package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class N {
    public static final N a;
    public static final N b;
    public static final N c;
    public static final /* synthetic */ N[] d;

    static {
        N n = new N("Start", 0);
        a = n;
        N n2 = new N("Game", 1);
        b = n2;
        N n3 = new N("End", 2);
        c = n3;
        N[] nArr = {n, n2, n3};
        d = nArr;
        AbstractC3328d.f(nArr);
    }

    public static N valueOf(String str) {
        return (N) Enum.valueOf(N.class, str);
    }

    public static N[] values() {
        return (N[]) d.clone();
    }
}
