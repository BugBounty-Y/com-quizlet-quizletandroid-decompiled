package com.perimeterx.mobile_sdk.web_view_interception;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final com.google.mlkit.common.internal.model.a a;
    public static final c b;
    public static final c c;
    public static final c d;
    public static final c e;
    public static final /* synthetic */ c[] f;

    static {
        c cVar = new c("START", 0);
        b = cVar;
        c cVar2 = new c("RENDERED", 1);
        c = cVar2;
        c cVar3 = new c("NOT_RENDERED", 2);
        d = cVar3;
        c cVar4 = new c("END", 3);
        e = cVar4;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4};
        f = cVarArr;
        AbstractC3328d.f(cVarArr);
        a = new com.google.mlkit.common.internal.model.a(23);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) f.clone();
    }

    public final String a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "captchaStart";
        }
        if (iOrdinal == 1) {
            return "captchaRendered";
        }
        if (iOrdinal == 2) {
            return "captchaNotRendered";
        }
        if (iOrdinal == 3) {
            return "captchaEnd";
        }
        throw new NoWhenBranchMatchedException();
    }
}
