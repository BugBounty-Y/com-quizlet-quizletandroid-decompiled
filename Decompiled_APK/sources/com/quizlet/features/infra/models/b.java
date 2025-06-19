package com.quizlet.features.infra.models;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final b b;
    public static final b c;
    public static final b d;
    public static final /* synthetic */ b[] e;
    public final int a;

    static {
        b bVar = new b("IN_TRANSITION", 0, 1);
        b = bVar;
        b bVar2 = new b("DOWNLOADED", 1, 2);
        c = bVar2;
        b bVar3 = new b("REMOVED", 2, -1);
        d = bVar3;
        b[] bVarArr = {bVar, bVar2, bVar3};
        e = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) e.clone();
    }
}
