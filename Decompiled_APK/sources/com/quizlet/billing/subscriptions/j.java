package com.quizlet.billing.subscriptions;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final j c;
    public static final j d;
    public static final /* synthetic */ j[] e;

    static {
        j jVar = new j("NO_UPGRADE", 0);
        j jVar2 = new j("GO", 1);
        a = jVar2;
        j jVar3 = new j("PLUS", 2);
        b = jVar3;
        j jVar4 = new j("TEACHER", 3);
        c = jVar4;
        j jVar5 = new j("PLUS_MONTHLY", 4);
        d = jVar5;
        j[] jVarArr = {jVar, jVar2, jVar3, jVar4, jVar5};
        e = jVarArr;
        AbstractC3328d.f(jVarArr);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) e.clone();
    }
}
