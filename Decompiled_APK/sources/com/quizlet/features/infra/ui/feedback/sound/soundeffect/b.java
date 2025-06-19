package com.quizlet.features.infra.ui.feedback.sound.soundeffect;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements a {
    public static final b b;
    public static final b c;
    public static final /* synthetic */ b[] d;
    public final int a;

    static {
        b bVar = new b("StudyCorrect", 0, R.raw.study_correct);
        b bVar2 = new b("StudyCheckpoint", 1, R.raw.study_checkpoint);
        b = bVar2;
        b bVar3 = new b("StudyComplete", 2, R.raw.study_complete);
        c = bVar3;
        b[] bVarArr = {bVar, bVar2, bVar3};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
