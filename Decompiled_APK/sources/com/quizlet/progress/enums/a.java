package com.quizlet.progress.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.firebase.heartbeatinfo.e;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final e b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final int a;

    static {
        a aVar = new a("INCORRECT", 0, 0);
        a aVar2 = new a("CORRECT", 1, 1);
        c = aVar2;
        a aVar3 = new a("SKIPPED", 2, 2);
        d = aVar3;
        a[] aVarArr = {aVar, aVar2, aVar3, new a("INCORRECT_WITH_HINT", 3, 3), new a("CORRECT_WITH_HINT", 4, 4)};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new e(29);
    }

    public a(String str, int i, int i2) {
        this.a = i2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
