package com.perimeterx.mobile_sdk.api_data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final j c;
    public static final j d;
    public static final j e;
    public static final j f;
    public static final j g;
    public static final j h;
    public static final j i;
    public static final j j;
    public static final /* synthetic */ j[] k;

    static {
        j jVar = new j("NEW_SESSION", 0);
        a = jVar;
        j jVar2 = new j("TOKEN_SCHEDULED_UPDATE", 1);
        b = jVar2;
        j jVar3 = new j("APP_RETURNS_FROM_BACKGROUND", 2);
        c = jVar3;
        j jVar4 = new j("REQUEST_WAS_BLOCKED", 3);
        j jVar5 = new j("MISSING_TOKEN_AFTER_CHALLENGE_SOLVED", 4);
        d = jVar5;
        j jVar6 = new j("FIRST_TOUCH_EVENT", 5);
        e = jVar6;
        j jVar7 = new j("SCHEDULED_REPORT", 6);
        f = jVar7;
        j jVar8 = new j("CAPACITY_IS_FULL", 7);
        g = jVar8;
        j jVar9 = new j("APP_WENT_TO_BACKGROUND", 8);
        h = jVar9;
        j jVar10 = new j("HYBRID_APP_EVENT", 9);
        i = jVar10;
        j jVar11 = new j("ACCOUNT_DEFENDER_EVENT", 10);
        j = jVar11;
        j[] jVarArr = {jVar, jVar2, jVar3, jVar4, jVar5, jVar6, jVar7, jVar8, jVar9, jVar10, jVar11};
        k = jVarArr;
        AbstractC3328d.f(jVarArr);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) k.clone();
    }
}
