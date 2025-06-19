package com.quizlet.learn.ui.progress;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.jvm.functions.Function2;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class i {
    public static final i c;
    public static final i d;
    public static final i e;
    public static final i f;
    public static final /* synthetic */ i[] g;
    public final Function2 a;
    public final Function2 b;

    static {
        i iVar = new i("UNANSWERED", 0, h.b, h.c);
        c = iVar;
        i iVar2 = new i("CORRECT", 1, h.d, h.e);
        d = iVar2;
        i iVar3 = new i("INCORRECT", 2, h.f, h.g);
        e = iVar3;
        i iVar4 = new i("SUMMARY", 3, h.h, h.i);
        f = iVar4;
        i[] iVarArr = {iVar, iVar2, iVar3, iVar4};
        g = iVarArr;
        AbstractC3328d.f(iVarArr);
    }

    public i(String str, int i, Function2 function2, Function2 function22) {
        this.a = function2;
        this.b = function22;
    }

    public static i valueOf(String str) {
        return (i) Enum.valueOf(i.class, str);
    }

    public static i[] values() {
        return (i[]) g.clone();
    }
}
