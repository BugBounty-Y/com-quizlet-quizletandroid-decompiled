package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class g {
    public static final g a;
    public static final g b;
    public static final g c;
    public static final g d;
    public static final g e;
    public static final g f;
    public static final g g;
    public static final g h;
    public static final g i;
    public static final g j;
    public static final g k;
    public static final /* synthetic */ g[] l;

    static {
        g gVar = new g("CONTENT_TYPE", 0);
        a = gVar;
        g gVar2 = new g("CONTENT_LENGTH", 1);
        g gVar3 = new g("USER_AGENT", 2);
        b = gVar3;
        g gVar4 = new g("PX_AUTHORIZATION", 3);
        c = gVar4;
        g gVar5 = new g("PX_ORIGINAL_TOKEN", 4);
        g gVar6 = new g("PX_MOBILE_SDK_VERSION", 5);
        d = gVar6;
        g gVar7 = new g("PX_OS", 6);
        e = gVar7;
        g gVar8 = new g("PX_OS_VERSION", 7);
        f = gVar8;
        g gVar9 = new g("PX_VID", 8);
        g = gVar9;
        g gVar10 = new g("PX_UUID", 9);
        h = gVar10;
        g gVar11 = new g("PX_DEVICE_FP", 10);
        i = gVar11;
        g gVar12 = new g("PX_DEVICE_MODEL", 11);
        j = gVar12;
        g gVar13 = new g("PX_ERROR", 12);
        k = gVar13;
        g[] gVarArr = {gVar, gVar2, gVar3, gVar4, gVar5, gVar6, gVar7, gVar8, gVar9, gVar10, gVar11, gVar12, gVar13};
        l = gVarArr;
        AbstractC3328d.f(gVarArr);
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) l.clone();
    }

    public final String a() {
        switch (ordinal()) {
            case 0:
                return "Content-Type";
            case 1:
                return "Content-Length";
            case 2:
                return "User-Agent";
            case 3:
                return "X-PX-AUTHORIZATION";
            case 4:
                return "X-PX-ORIGINAL-TOKEN";
            case 5:
                return "X-PX-MOBILE-SDK-VERSION";
            case 6:
                return "X-PX-OS";
            case 7:
                return "X-PX-OS-VERSION";
            case 8:
                return "X-PX-VID";
            case 9:
                return "X-PX-UUID";
            case 10:
                return "X-PX-DEVICE-FP";
            case 11:
                return "X-PX-DEVICE-MODEL";
            case 12:
                return "X-PX-HELLO";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
