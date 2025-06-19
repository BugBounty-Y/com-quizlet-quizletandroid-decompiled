package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

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
    public static final /* synthetic */ e[] l;

    static {
        e eVar = new e("EXCEPTION_NAME", 0);
        a = eVar;
        e eVar2 = new e("EXCEPTION_REASON", 1);
        b = eVar2;
        e eVar3 = new e("EXCEPTION_USER_INFO", 2);
        e eVar4 = new e("EXCEPTION_CALL_STACK_SYMBOLS", 3);
        c = eVar4;
        e eVar5 = new e("TIMESTAMP", 4);
        d = eVar5;
        e eVar6 = new e("APP_ID", 5);
        e = eVar6;
        e eVar7 = new e("SDK_VERSION", 6);
        f = eVar7;
        e eVar8 = new e("APP_NAME", 7);
        g = eVar8;
        e eVar9 = new e("APP_VERSION", 8);
        h = eVar9;
        e eVar10 = new e("BUNDLE_IDENTIFIER", 9);
        i = eVar10;
        e eVar11 = new e("DEVICE_MODEL", 10);
        j = eVar11;
        e eVar12 = new e("OS_VERSION", 11);
        k = eVar12;
        e[] eVarArr = {eVar, eVar2, eVar3, eVar4, eVar5, eVar6, eVar7, eVar8, eVar9, eVar10, eVar11, eVar12};
        l = eVarArr;
        AbstractC3328d.f(eVarArr);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) l.clone();
    }

    public final String a() {
        switch (ordinal()) {
            case 0:
                return "crash_name";
            case 1:
                return "crash_reason";
            case 2:
                return "user_info";
            case 3:
                return "callstack";
            case 4:
                return "timestamp";
            case 5:
                return "app_id";
            case 6:
                return "sdk_version";
            case 7:
                return "app_name";
            case 8:
                return "host_app_version";
            case 9:
                return "bundle_identifier";
            case 10:
                return "device_model";
            case 11:
                return "device_os_version";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
