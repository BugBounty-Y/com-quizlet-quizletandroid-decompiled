package com.quizlet.features.subjects.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final c c;
    public static final c d;
    public static final c e;
    public static final /* synthetic */ c[] f;

    static {
        c cVar = new c("BRAZIL", 0);
        a = cVar;
        c cVar2 = new c("PHILIPPINES", 1);
        b = cVar2;
        c cVar3 = new c("VIETNAM", 2);
        c = cVar3;
        c cVar4 = new c("MEXICO", 3);
        d = cVar4;
        c cVar5 = new c("US", 4);
        e = cVar5;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4, cVar5};
        f = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) f.clone();
    }
}
