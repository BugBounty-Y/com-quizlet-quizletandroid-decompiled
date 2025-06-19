package com.quizlet.features.folders.addtofolder.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class o {
    public static final o a;
    public static final o b;
    public static final o c;
    public static final /* synthetic */ o[] d;

    static {
        o oVar = new o("FlashcardSets", 0);
        a = oVar;
        o oVar2 = new o("StudyGuides", 1);
        b = oVar2;
        o oVar3 = new o("ExpertSolutions", 2);
        c = oVar3;
        o[] oVarArr = {oVar, oVar2, oVar3};
        d = oVarArr;
        AbstractC3328d.f(oVarArr);
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) d.clone();
    }
}
