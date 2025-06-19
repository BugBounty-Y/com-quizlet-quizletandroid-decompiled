package com.braze.triggers.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class b {
    public static final b a;
    public static final b b;
    public static final b c;
    public static final /* synthetic */ b[] d;

    static {
        b bVar = new b("ZIP", 0);
        a = bVar;
        b bVar2 = new b("IMAGE", 1);
        b = bVar2;
        b bVar3 = new b("FILE", 2);
        c = bVar3;
        b[] bVarArr = {bVar, bVar2, bVar3};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i) {
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
