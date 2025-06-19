package com.perimeterx.mobile_sdk.local_data;

import android.app.Application;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class w {
    public static final w a = new w();
    public static Application b;
    public static b c;

    public static String a(x key, String appId) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        b bVar = c;
        if (bVar != null) {
            return bVar.a(key, appId);
        }
        Intrinsics.m("storage");
        throw null;
    }

    public static void b(b bVar, ArrayList arrayList) {
        y yVar;
        x xVar = x.a;
        Boolean boolE = bVar.e(xVar, "PXSDK");
        if (boolE == null || boolE.equals(Boolean.FALSE)) {
            return;
        }
        bVar.d(false, xVar, "PXSDK");
        for (x xVar2 : x.values()) {
            Iterator it2 = arrayList.iterator();
            Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
            while (it2.hasNext()) {
                Object next = it2.next();
                Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                String str = (String) next;
                switch (xVar2.ordinal()) {
                    case 0:
                        yVar = y.c;
                        break;
                    case 1:
                    case 2:
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                        yVar = y.a;
                        break;
                    case 3:
                        yVar = y.b;
                        break;
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                int iOrdinal = yVar.ordinal();
                if (iOrdinal == 0) {
                    String strA = bVar.a(xVar2, str);
                    if (strA != null) {
                        b bVar2 = c;
                        if (bVar2 == null) {
                            Intrinsics.m("storage");
                            throw null;
                        }
                        bVar2.c(strA, xVar2, str);
                    }
                    bVar.c("", xVar2, str);
                } else if (iOrdinal == 1) {
                    Integer numF = bVar.f(xVar2, str);
                    if (numF != null) {
                        int iIntValue = numF.intValue();
                        b bVar3 = c;
                        if (bVar3 == null) {
                            Intrinsics.m("storage");
                            throw null;
                        }
                        bVar3.b(iIntValue, xVar2, str);
                    }
                    bVar.b(0, xVar2, str);
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    Boolean boolE2 = bVar.e(xVar2, str);
                    if (boolE2 != null) {
                        boolean zBooleanValue = boolE2.booleanValue();
                        b bVar4 = c;
                        if (bVar4 == null) {
                            Intrinsics.m("storage");
                            throw null;
                        }
                        bVar4.d(zBooleanValue, xVar2, str);
                    }
                    bVar.d(false, xVar2, str);
                }
            }
        }
        Iterator it3 = arrayList.iterator();
        Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
        while (it3.hasNext()) {
            Object next2 = it3.next();
            Intrinsics.checkNotNullExpressionValue(next2, "next(...)");
            bVar.a((String) next2);
        }
    }

    public static void c(String str, x key, String appId) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        b bVar = c;
        if (bVar == null) {
            Intrinsics.m("storage");
            throw null;
        }
        if (str == null) {
            str = "";
        }
        bVar.c(str, key, appId);
    }
}
