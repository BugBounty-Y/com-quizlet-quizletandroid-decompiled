package com.google.android.gms.internal.mlkit_vision_camera;

import android.text.Editable;
import assistantMode.types.C1454a;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class V2 {
    public static final /* synthetic */ int a = 0;

    public static void a(org.wordpress.aztec.spans.H h, Editable output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(output, "output");
        T2.c(h, output, i, i2);
    }

    public static final LinkedHashMap b(List cards) {
        Intrinsics.checkNotNullParameter(cards, "cards");
        List list = assistantMode.a.b;
        int iA = kotlin.collections.U.a(kotlin.collections.C.q(list, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : list) {
            assistantMode.enums.m mVar = (assistantMode.enums.m) obj;
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : cards) {
                if (((C1454a) obj2).f(kotlin.collections.A.b(mVar))) {
                    arrayList.add(obj2);
                }
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(Long.valueOf(((C1454a) it2.next()).a.a));
            }
            linkedHashMap.put(obj, CollectionsKt.A0(arrayList2));
        }
        return linkedHashMap;
    }
}
