package com.quizlet.features.infra.basestudy.data.models.logging;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final /* synthetic */ a[] a;

    static {
        a[] aVarArr = {new a("TEST_STUDY_CARD_PLAY_AUDIO", 0), new a("TEST_STUDY_BACK_BUTTON_CLICKED", 1), new a("TEST_RESULTS_NEXT_ACTION_BUTTON_CLICKED", 2)};
        a = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) a.clone();
    }
}
