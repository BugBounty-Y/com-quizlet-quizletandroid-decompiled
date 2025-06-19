package com.google.android.gms.internal.mlkit_vision_camera;

import java.util.Map;
import kotlin.collections.AbstractC4922m;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C1 {
    public static final /* synthetic */ int a = 0;

    public static boolean a(AbstractC4922m map, Map.Entry element) {
        Intrinsics.checkNotNullParameter(map, "map");
        Intrinsics.checkNotNullParameter(element, "element");
        V v = map.get(element.getKey());
        return v != 0 ? v.equals(element.getValue()) : element.getValue() == null && map.containsKey(element.getKey());
    }

    public static final String b(C4950i c4950i) {
        Intrinsics.checkNotNullParameter(c4950i, "<this>");
        return c4950i.e();
    }
}
