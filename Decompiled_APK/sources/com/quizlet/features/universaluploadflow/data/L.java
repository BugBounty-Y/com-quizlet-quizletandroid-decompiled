package com.quizlet.features.universaluploadflow.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class L {
    public static final L a;
    public static final L b;
    public static final L c;
    public static final L d;
    public static final /* synthetic */ L[] e;

    static {
        L l = new L("PASTE_TEXT", 0);
        a = l;
        L l2 = new L("IMAGE", 1);
        b = l2;
        L l3 = new L("FILE", 2);
        c = l3;
        L l4 = new L("STUDY_SET", 3);
        d = l4;
        L[] lArr = {l, l2, l3, l4};
        e = lArr;
        AbstractC3328d.f(lArr);
    }

    public static L valueOf(String str) {
        return (L) Enum.valueOf(L.class, str);
    }

    public static L[] values() {
        return (L[]) e.clone();
    }
}
