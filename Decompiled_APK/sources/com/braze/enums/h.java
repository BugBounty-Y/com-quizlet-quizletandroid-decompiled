package com.braze.enums;

import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class h implements IPutIntoJson {
    public static final h a;
    public static final h b;
    public static final /* synthetic */ h[] c;

    static {
        h hVar = new h("SUBSCRIBED", 0);
        a = hVar;
        h hVar2 = new h("UNSUBSCRIBED", 1);
        b = hVar2;
        h[] hVarArr = {hVar, hVar2};
        c = hVarArr;
        AbstractC3328d.f(hVarArr);
    }

    public h(String str, int i) {
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) c.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "subscribed";
        }
        if (iOrdinal == 1) {
            return "unsubscribed";
        }
        throw new NoWhenBranchMatchedException();
    }
}
