package com.quizlet.diagrams;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final b b;
    public static final b c;
    public static final /* synthetic */ b[] d;
    public final String a;

    static {
        b bVar = new b("DISABLE_ZOOM", 0, "setVariant('NO_ZOOM_VARIANT');");
        b = bVar;
        b bVar2 = new b("SHOW_NUMBER_OF_LOCATION_BADGE", 1, "showNumberOfLocationsBadge(true);");
        c = bVar2;
        b[] bVarArr = {bVar, bVar2};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, String str2) {
        this.a = str2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
