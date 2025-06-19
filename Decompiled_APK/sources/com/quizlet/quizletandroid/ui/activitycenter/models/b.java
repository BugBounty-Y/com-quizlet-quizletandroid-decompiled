package com.quizlet.quizletandroid.ui.activitycenter.models;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final a c;
    public static final /* synthetic */ b[] d;
    public final String a;
    public final int b;

    static {
        b[] bVarArr = {new b("FLASHCARDS", 0, "flashcards", R.drawable.ic_study_flashcards), new b("LEARN", 1, "learn", 2131231428), new b("LIVE", 2, "live", R.drawable.ic_study_live), new b("MATCH", 3, "match", R.drawable.ic_study_match), new b("SPELL", 4, "spell", R.drawable.ic_study_spell), new b("TEST", 5, "test", R.drawable.ic_study_test), new b("WRITE", 6, "write", R.drawable.ic_study_write)};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
        c = new a();
    }

    public b(String str, int i, String str2, int i2) {
        this.a = str2;
        this.b = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
