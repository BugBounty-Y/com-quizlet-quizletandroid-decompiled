package com.quizlet.uicommon.ui.common.widgets;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class i {
    public static final i a;
    public static final i b;
    public static final i c;
    public static final /* synthetic */ i[] d;

    static {
        i iVar = new i("LEFT", 0);
        a = iVar;
        i iVar2 = new i("MIDDLE", 1);
        b = iVar2;
        i iVar3 = new i("RIGHT", 2);
        c = iVar3;
        i[] iVarArr = {iVar, iVar2, iVar3};
        d = iVarArr;
        AbstractC3328d.f(iVarArr);
    }

    public static i valueOf(String str) {
        return (i) Enum.valueOf(i.class, str);
    }

    public static i[] values() {
        return (i[]) d.clone();
    }
}
