package org.wordpress.aztec.toolbar;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final e c;
    public static final e d;
    public static final e e;
    public static final /* synthetic */ e[] f;

    static {
        e eVar = new e("INLINE_STYLE", 0);
        a = eVar;
        e eVar2 = new e("EXCLUSIVE_INLINE_STYLE", 1);
        b = eVar2;
        e eVar3 = new e("BLOCK_STYLE", 2);
        c = eVar3;
        e eVar4 = new e("LINE_BLOCK", 3);
        d = eVar4;
        e eVar5 = new e("OTHER", 4);
        e = eVar5;
        e[] eVarArr = {eVar, eVar2, eVar3, eVar4, eVar5};
        f = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) f.clone();
    }
}
