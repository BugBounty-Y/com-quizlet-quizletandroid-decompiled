package com.quizlet.features.userprofile.ui;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final int a;
    public final int b;

    static {
        a aVar = new a("SETTINGS", 0, 2131231554, R.string.your_settings);
        c = aVar;
        a aVar2 = new a("ACTIVITY", 1, R.drawable.ic_sys_bell, R.string.activity);
        d = aVar2;
        a[] aVarArr = {aVar, aVar2};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public a(String str, int i, int i2, int i3) {
        this.a = i2;
        this.b = i3;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
