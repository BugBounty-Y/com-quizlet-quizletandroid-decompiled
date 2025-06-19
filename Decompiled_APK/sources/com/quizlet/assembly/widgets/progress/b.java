package com.quizlet.assembly.widgets.progress;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.jvm.functions.Function2;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final b d;
    public static final b e;
    public static final b f;
    public static final /* synthetic */ b[] g;
    public final Function2 a;
    public final Function2 b;
    public final Function2 c;

    static {
        b bVar = new b("KNOW", 0, a.b, a.c, a.d);
        d = bVar;
        b bVar2 = new b("STILL_LEARNING", 1, a.e, a.f, a.g);
        e = bVar2;
        b bVar3 = new b("LEFT", 2, a.h, a.i, a.j);
        f = bVar3;
        b[] bVarArr = {bVar, bVar2, bVar3};
        g = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, Function2 function2, Function2 function22, Function2 function23) {
        this.a = function2;
        this.b = function22;
        this.c = function23;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) g.clone();
    }
}
