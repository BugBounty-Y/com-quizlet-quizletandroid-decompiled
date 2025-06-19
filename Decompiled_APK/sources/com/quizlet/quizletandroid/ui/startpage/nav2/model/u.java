package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class u {
    public static final u a;
    public static final u b;
    public static final u c;
    public static final u d;
    public static final u e;
    public static final u f;
    public static final u g;
    public static final u h;
    public static final /* synthetic */ u[] i;

    static {
        u uVar = new u("USER_BASED_REC_SET", 0);
        a = uVar;
        u uVar2 = new u("SCHOOL_COURSE_REC_SET", 1);
        b = uVar2;
        u uVar3 = new u("AGE_LOCATION_REC_SET", 2);
        c = uVar3;
        u uVar4 = new u("SET", 3);
        d = uVar4;
        u uVar5 = new u("FOLDER", 4);
        e = uVar5;
        u uVar6 = new u("CLASSES", 5);
        f = uVar6;
        u uVar7 = new u("EXPLANATIONS", 6);
        g = uVar7;
        u uVar8 = new u("NOTE", 7);
        h = uVar8;
        u[] uVarArr = {uVar, uVar2, uVar3, uVar4, uVar5, uVar6, uVar7, uVar8};
        i = uVarArr;
        AbstractC3328d.f(uVarArr);
    }

    public static u valueOf(String str) {
        return (u) Enum.valueOf(u.class, str);
    }

    public static u[] values() {
        return (u[]) i.clone();
    }
}
