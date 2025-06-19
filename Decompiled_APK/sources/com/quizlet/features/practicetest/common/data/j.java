package com.quizlet.features.practicetest.common.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final j c;
    public static final j d;
    public static final j e;
    public static final j f;
    public static final /* synthetic */ j[] g;

    static {
        j jVar = new j("UNANSWERED", 0);
        a = jVar;
        j jVar2 = new j("ANSWERED", 1);
        b = jVar2;
        j jVar3 = new j("REMOVED", 2);
        c = jVar3;
        j jVar4 = new j("CORRECT", 3);
        d = jVar4;
        j jVar5 = new j("INCORRECT", 4);
        e = jVar5;
        j jVar6 = new j("SKIPPED", 5);
        f = jVar6;
        j[] jVarArr = {jVar, jVar2, jVar3, jVar4, jVar5, jVar6};
        g = jVarArr;
        AbstractC3328d.f(jVarArr);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) g.clone();
    }
}
