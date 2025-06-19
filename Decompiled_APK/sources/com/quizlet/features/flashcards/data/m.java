package com.quizlet.features.flashcards.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class m {
    public static final m a;
    public static final m b;
    public static final m c;
    public static final m d;
    public static final m e;
    public static final m f;
    public static final m g;
    public static final m h;
    public static final /* synthetic */ m[] i;

    static {
        m mVar = new m("FLIP", 0);
        a = mVar;
        m mVar2 = new m("STILL_LEARNING", 1);
        b = mVar2;
        m mVar3 = new m("KNOW", 2);
        c = mVar3;
        m mVar4 = new m("SWIPE", 3);
        d = mVar4;
        m mVar5 = new m("UNDO", 4);
        e = mVar5;
        m mVar6 = new m("SETTINGS", 5);
        f = mVar6;
        m mVar7 = new m("AUTO_PLAY_ON", 6);
        g = mVar7;
        m mVar8 = new m("AUTO_PLAY_OFF", 7);
        h = mVar8;
        m[] mVarArr = {mVar, mVar2, mVar3, mVar4, mVar5, mVar6, mVar7, mVar8};
        i = mVarArr;
        AbstractC3328d.f(mVarArr);
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) i.clone();
    }
}
