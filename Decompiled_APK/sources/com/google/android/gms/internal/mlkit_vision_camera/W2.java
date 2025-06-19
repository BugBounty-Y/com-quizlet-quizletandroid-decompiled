package com.google.android.gms.internal.mlkit_vision_camera;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class W2 {
    public static final /* synthetic */ int a = 0;

    public static String a(org.wordpress.aztec.spans.M m) {
        if (m.f().getLength() == 0) {
            return m.u();
        }
        return m.u() + ' ' + m.f();
    }

    public static final List b(LinkedHashMap idsWithContentByCardSide) {
        Intrinsics.checkNotNullParameter(idsWithContentByCardSide, "idsWithContentByCardSide");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : idsWithContentByCardSide.entrySet()) {
            if (!((Collection) entry.getValue()).isEmpty()) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        return CollectionsKt.w0(linkedHashMap.keySet());
    }
}
