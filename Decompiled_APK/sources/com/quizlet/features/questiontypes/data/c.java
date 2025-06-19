package com.quizlet.features.questiontypes.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final c c;
    public static final c d;
    public static final /* synthetic */ c[] e;

    static {
        c cVar = new c("MULTIPLE_CHOICE", 0);
        a = cVar;
        c cVar2 = new c("FILL_IN_THE_BLANK", 1);
        b = cVar2;
        c cVar3 = new c("WRITTEN", 2);
        c = cVar3;
        c cVar4 = new c("REVEAL_SELF_ASSESSMENT", 3);
        d = cVar4;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4};
        e = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) e.clone();
    }
}
