package com.quizlet.features.emailconfirmation.data.events;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final c c;
    public static final /* synthetic */ c[] d;

    static {
        c cVar = new c("Success", 0);
        a = cVar;
        c cVar2 = new c("FailEmailNotFound", 1);
        b = cVar2;
        c cVar3 = new c("FailUnknown", 2);
        c = cVar3;
        c[] cVarArr = {cVar, cVar2, cVar3};
        d = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) d.clone();
    }
}
