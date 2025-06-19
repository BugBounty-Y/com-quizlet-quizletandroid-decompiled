package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final h e;
    public static final h f;
    public static final /* synthetic */ h[] g;

    static {
        h hVar = new h("CONTENT_TYPE_APPLICATION_JSON", 0);
        h hVar2 = new h("CONTENT_TYPE_APPLICATION_FORM", 1);
        a = hVar2;
        h hVar3 = new h("PX_AUTHORIZATION_NO_TOKEN", 2);
        b = hVar3;
        h hVar4 = new h("PX_CONNECTION_ERROR_CODE", 3);
        c = hVar4;
        h hVar5 = new h("PX_PINNING_ERROR_CODE", 4);
        d = hVar5;
        h hVar6 = new h("PX_USER_AGENT", 5);
        e = hVar6;
        h hVar7 = new h("PX_ANDROID_VALUE", 6);
        f = hVar7;
        h[] hVarArr = {hVar, hVar2, hVar3, hVar4, hVar5, hVar6, hVar7};
        g = hVarArr;
        AbstractC3328d.f(hVarArr);
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) g.clone();
    }

    public final String a() {
        switch (ordinal()) {
            case 0:
                return "application/json";
            case 1:
                return "application/x-www-form-urlencoded; charset=utf-8";
            case 2:
                return "1";
            case 3:
                return "2";
            case 4:
                return "3";
            case 5:
                return "PerimeterX Android SDK/";
            case 6:
                return "Android";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
