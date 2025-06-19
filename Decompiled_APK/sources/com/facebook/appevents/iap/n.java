package com.facebook.appevents.iap;

import android.os.Bundle;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3559x2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class n {
    public static final List a = A.b("fb_currency");
    public static final List b = A.b("_valueToSum");
    public static final long c = TimeUnit.MINUTES.toMillis(1);
    public static final List d = B.j(new Pair("fb_iap_product_id", A.b("fb_iap_product_id")), new Pair("fb_iap_product_description", A.b("fb_iap_product_description")), new Pair("fb_iap_product_title", A.b("fb_iap_product_title")), new Pair("fb_iap_purchase_token", A.b("fb_iap_purchase_token")));

    public static Pair a(Bundle bundle, Bundle bundle2, com.facebook.appevents.q qVar) {
        if (bundle == null) {
            return new Pair(bundle2, qVar);
        }
        try {
            for (String key : bundle.keySet()) {
                String string = bundle.getString(key);
                if (string != null) {
                    Map map = com.facebook.appevents.q.b;
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Pair pairB = AbstractC3559x2.b(key, string, bundle2, qVar);
                    Bundle bundle3 = (Bundle) pairB.a;
                    qVar = (com.facebook.appevents.q) pairB.b;
                    bundle2 = bundle3;
                }
            }
        } catch (Exception unused) {
        }
        return new Pair(bundle2, qVar);
    }

    public static List b(boolean z) {
        v vVarB = y.b(com.facebook.o.b());
        if ((vVarB != null ? vVarB.v : null) == null || vVarB.v.isEmpty()) {
            return d;
        }
        ArrayList<Pair> arrayList = vVarB.v;
        if (!z) {
            return arrayList;
        }
        ArrayList arrayList2 = new ArrayList();
        for (Pair pair : arrayList) {
            Iterator it2 = ((List) pair.b).iterator();
            while (it2.hasNext()) {
                arrayList2.add(new Pair((String) it2.next(), A.b(pair.a)));
            }
        }
        return arrayList2;
    }

    public static List c(boolean z) {
        ArrayList<Pair> arrayList;
        v vVarB = y.b(com.facebook.o.b());
        if (vVarB == null || (arrayList = vVarB.w) == null || arrayList.isEmpty()) {
            return null;
        }
        if (!z) {
            return arrayList;
        }
        ArrayList arrayList2 = new ArrayList();
        for (Pair pair : arrayList) {
            Iterator it2 = ((List) pair.b).iterator();
            while (it2.hasNext()) {
                arrayList2.add(new Pair((String) it2.next(), A.b(pair.a)));
            }
        }
        return arrayList2;
    }
}
