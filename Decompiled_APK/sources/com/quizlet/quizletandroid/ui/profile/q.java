package com.quizlet.quizletandroid.ui.profile;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class q {
    public static final p b;
    public static final q c;
    public static final q d;
    public static final q e;
    public static final q f;
    public static final /* synthetic */ q[] g;
    public final int a;

    static {
        q qVar = new q("ACHIEVEMENTS", 0, R.string.new_profile_achievements_tab_title);
        c = qVar;
        q qVar2 = new q("SET_LIST", 1, R.string.new_profile_sets_tab_title);
        d = qVar2;
        q qVar3 = new q("CLASS_LIST", 2, R.string.new_profile_classes_tab_title);
        e = qVar3;
        q qVar4 = new q("FOLDER_LIST", 3, R.string.new_profile_folders_tab_title);
        f = qVar4;
        q[] qVarArr = {qVar, qVar2, qVar3, qVar4};
        g = qVarArr;
        AbstractC3328d.f(qVarArr);
        b = new p(0);
    }

    public q(String str, int i, int i2) {
        this.a = i2;
    }

    public static q valueOf(String str) {
        return (q) Enum.valueOf(q.class, str);
    }

    public static q[] values() {
        return (q[]) g.clone();
    }
}
