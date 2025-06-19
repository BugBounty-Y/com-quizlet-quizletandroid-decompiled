package com.perimeterx.mobile_sdk.local_data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class x {
    public static final x a;
    public static final x b;
    public static final x c;
    public static final x d;
    public static final x e;
    public static final x f;
    public static final x g;
    public static final x h;
    public static final x i;
    public static final /* synthetic */ x[] j;

    static {
        x xVar = new x("STORAGE_ENABLED", 0);
        a = xVar;
        x xVar2 = new x("VID", 1);
        b = xVar2;
        x xVar3 = new x("TOKEN", 2);
        c = xVar3;
        x xVar4 = new x("RESUME_COUNTER", 3);
        d = xVar4;
        x xVar5 = new x("EXCEPTION", 4);
        e = xVar5;
        x xVar6 = new x("USER_ID", 5);
        f = xVar6;
        x xVar7 = new x("OLD_USER_ID", 6);
        g = xVar7;
        x xVar8 = new x("PREVIOUS_DOCTOR_SUMMARY", 7);
        h = xVar8;
        x xVar9 = new x("DOCTOR_VERSION", 8);
        i = xVar9;
        x[] xVarArr = {xVar, xVar2, xVar3, xVar4, xVar5, xVar6, xVar7, xVar8, xVar9};
        j = xVarArr;
        AbstractC3328d.f(xVarArr);
    }

    public static x valueOf(String str) {
        return (x) Enum.valueOf(x.class, str);
    }

    public static x[] values() {
        return (x[]) j.clone();
    }

    public final String a() {
        switch (ordinal()) {
            case 0:
                return "storage_enabled";
            case 1:
                return "vid";
            case 2:
                return "token";
            case 3:
                return "resume_counter";
            case 4:
                return "exception";
            case 5:
                return "user_id";
            case 6:
                return "old_user_id";
            case 7:
                return "previous_doctor_summary";
            case 8:
                return "doctor_version";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
