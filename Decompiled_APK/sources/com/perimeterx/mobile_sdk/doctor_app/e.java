package com.perimeterx.mobile_sdk.doctor_app;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final e c;
    public static final e d;
    public static final e e;
    public static final e f;
    public static final e g;
    public static final e h;
    public static final e i;
    public static final e j;
    public static final e k;
    public static final e l;
    public static final /* synthetic */ e[] m;

    static {
        e eVar = new e("UPDATE_STATE", 0);
        a = eVar;
        e eVar2 = new e("SHOW_DOCTOR", 1);
        b = eVar2;
        e eVar3 = new e("HIDE_DOCTOR", 2);
        c = eVar3;
        e eVar4 = new e("DESTROY_DOCTOR", 3);
        d = eVar4;
        e eVar5 = new e("SHOW_POPUP", 4);
        e = eVar5;
        e eVar6 = new e("START_NATIVE_CHECK", 5);
        f = eVar6;
        e eVar7 = new e("START_WEB_VIEW_CHECK", 6);
        g = eVar7;
        e eVar8 = new e("SAVE_CURRENT_SUMMARY", 7);
        h = eVar8;
        e eVar9 = new e("LOAD_PREVIOUS_SUMMARY", 8);
        i = eVar9;
        e eVar10 = new e("SET_EXPORTED_FOR_CURRENT_SUMMARY", 9);
        j = eVar10;
        e eVar11 = new e("START_NEW_SESSION", 10);
        k = eVar11;
        e eVar12 = new e("KILL_APP", 11);
        l = eVar12;
        e[] eVarArr = {eVar, eVar2, eVar3, eVar4, eVar5, eVar6, eVar7, eVar8, eVar9, eVar10, eVar11, eVar12};
        m = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) m.clone();
    }
}
