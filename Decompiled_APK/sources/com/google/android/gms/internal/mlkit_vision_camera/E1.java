package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.navigation.C1289k;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E1 {
    public static final /* synthetic */ int a = 0;

    public static final void a(kotlinx.coroutines.channels.w wVar, Throwable th) {
        CancellationException cancellationExceptionA = th instanceof CancellationException ? (CancellationException) th : null;
        if (cancellationExceptionA == null) {
            cancellationExceptionA = kotlinx.coroutines.E.a("Channel was consumed, consumer had failed", th);
        }
        wVar.j(cancellationExceptionA);
    }

    public static final ArrayList b(Map map, Function1 isArgumentMissing) {
        Intrinsics.checkNotNullParameter(map, "<this>");
        Intrinsics.checkNotNullParameter(isArgumentMissing, "isArgumentMissing");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : map.entrySet()) {
            C1289k c1289k = (C1289k) entry.getValue();
            Boolean boolValueOf = c1289k != null ? Boolean.valueOf(c1289k.b) : null;
            Intrinsics.d(boolValueOf);
            if (!boolValueOf.booleanValue() && !c1289k.c) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        Set setKeySet = linkedHashMap.keySet();
        ArrayList arrayList = new ArrayList();
        for (Object obj : setKeySet) {
            if (((Boolean) isArgumentMissing.invoke((String) obj)).booleanValue()) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }
}
