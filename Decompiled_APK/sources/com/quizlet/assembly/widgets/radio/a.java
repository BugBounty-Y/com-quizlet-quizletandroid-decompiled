package com.quizlet.assembly.widgets.radio;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import retrofit2.adapter.rxjava3.d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final d b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final int a;

    static {
        a aVar = new a("BASIC", 0, 0);
        c = aVar;
        a aVar2 = new a("DISABLED", 1, 1);
        d = aVar2;
        a[] aVarArr = {aVar, aVar2, new a("INVALID", 2, 2)};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new d(23);
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
