package com.quizlet.explanations.feedback.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final /* synthetic */ c[] c;

    static {
        c cVar = new c("ReportThisContent", 0);
        a = cVar;
        c cVar2 = new c("ThanksForReporting", 1);
        b = cVar2;
        c[] cVarArr = {cVar, cVar2};
        c = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) c.clone();
    }
}
