package com.quizlet.features.setpage.shareset;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final b d;
    public static final b e;
    public static final /* synthetic */ b[] f;
    public final int a;
    public final String b;
    public final int c;

    static {
        e[] eVarArr = e.a;
        b bVar = new b("TEACHER", "👍", 0, 1, R.string.share_set_message_teachers);
        d = bVar;
        b bVar2 = new b("STUDENT_AND_UNKNOWN", "😎", 1, 2, R.string.share_set_message_students);
        e = bVar2;
        b[] bVarArr = {bVar, bVar2};
        f = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, String str2, int i, int i2, int i3) {
        this.a = i2;
        this.b = str2;
        this.c = i3;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) f.clone();
    }
}
