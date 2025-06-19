package com.perimeterx.mobile_sdk.logger;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final /* synthetic */ c[] c;

    static {
        c cVar = new c("USER_INFO", 0);
        a = cVar;
        c cVar2 = new c("ERROR", 1);
        b = cVar2;
        c[] cVarArr = {cVar, cVar2, new c("EXCEPTION", 2), new c("APP_ID", 3)};
        c = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) c.clone();
    }

    public final String a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "user_info";
        }
        if (iOrdinal == 1) {
            return "error";
        }
        if (iOrdinal == 2) {
            return "exception";
        }
        if (iOrdinal == 3) {
            return "app_id";
        }
        throw new NoWhenBranchMatchedException();
    }
}
