package com.perimeterx.mobile_sdk.doctor_app.ui;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class i {
    public static final i a;
    public static final i b;
    public static final /* synthetic */ i[] c;

    static {
        i iVar = new i("NATIVE_CHECK_STARTED", 0);
        a = iVar;
        i iVar2 = new i("WEB_VIEW_CHECK_STARTED", 1);
        b = iVar2;
        i[] iVarArr = {iVar, iVar2};
        c = iVarArr;
        AbstractC3328d.f(iVarArr);
    }

    public static i valueOf(String str) {
        return (i) Enum.valueOf(i.class, str);
    }

    public static i[] values() {
        return (i[]) c.clone();
    }
}
