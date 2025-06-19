package com.google.android.gms.internal.mlkit_vision_camera;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class w3 {
    public static final /* synthetic */ int a = 0;

    public static coil3.network.t a(okio.A a2) throws NumberFormatException {
        int i = Integer.parseInt(a2.y(Long.MAX_VALUE));
        long j = Long.parseLong(a2.y(Long.MAX_VALUE));
        long j2 = Long.parseLong(a2.y(Long.MAX_VALUE));
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        int i2 = Integer.parseInt(a2.y(Long.MAX_VALUE));
        for (int i3 = 0; i3 < i2; i3++) {
            String strY = a2.y(Long.MAX_VALUE);
            int iL = StringsKt.L(strY, ':', 0, false, 6);
            if (iL == -1) {
                throw new IllegalArgumentException("Unexpected header: ".concat(strY).toString());
            }
            String strSubstring = strY.substring(0, iL);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            String string = StringsKt.g0(strSubstring).toString();
            String strSubstring2 = strY.substring(iL + 1);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
            String lowerCase = string.toLowerCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            Object arrayList = linkedHashMap.get(lowerCase);
            if (arrayList == null) {
                arrayList = new ArrayList();
                linkedHashMap.put(lowerCase, arrayList);
            }
            ((List) arrayList).add(strSubstring2);
        }
        return new coil3.network.t(i, j, j2, new coil3.network.r(kotlin.collections.V.l(linkedHashMap)), null, null);
    }

    public static void b(coil3.network.t tVar, okio.z zVar) {
        zVar.h0(tVar.a);
        zVar.v(10);
        zVar.h0(tVar.b);
        zVar.v(10);
        zVar.h0(tVar.c);
        zVar.v(10);
        Set<Map.Entry> setEntrySet = tVar.d.a.entrySet();
        Iterator it2 = setEntrySet.iterator();
        int size = 0;
        while (it2.hasNext()) {
            size += ((List) ((Map.Entry) it2.next()).getValue()).size();
        }
        zVar.h0(size);
        zVar.v(10);
        for (Map.Entry entry : setEntrySet) {
            for (String str : (List) entry.getValue()) {
                zVar.H((String) entry.getKey());
                zVar.H(":");
                zVar.H(str);
                zVar.v(10);
            }
        }
    }
}
