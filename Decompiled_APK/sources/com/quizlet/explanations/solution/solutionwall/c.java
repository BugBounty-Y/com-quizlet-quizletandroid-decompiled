package com.quizlet.explanations.solution.solutionwall;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final com.google.firebase.heartbeatinfo.e a;
    public static final /* synthetic */ c[] b;

    static {
        c[] cVarArr = {new c("Paywall", 0), new c("SignUpWall", 1), new c("LimitedContentWall", 2)};
        b = cVarArr;
        AbstractC3328d.f(cVarArr);
        a = new com.google.firebase.heartbeatinfo.e(25);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) b.clone();
    }
}
