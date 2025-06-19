package com.quizlet.learn.ads;

import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ AdManagerAdRequest.Builder a;

    public b(AdManagerAdRequest.Builder builder) {
        this.a = builder;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        AdManagerAdRequest.Builder builder;
        Pair pair = (Pair) obj;
        Intrinsics.checkNotNullParameter(pair, "<destruct>");
        Object obj2 = pair.a;
        Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
        Object obj3 = pair.b;
        Intrinsics.checkNotNullExpressionValue(obj3, "component2(...)");
        Map map = (Map) obj3;
        Iterator it2 = ((Map) obj2).entrySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            builder = this.a;
            if (!zHasNext) {
                break;
            }
            Map.Entry entry = (Map.Entry) it2.next();
            builder.addCustomTargeting((String) entry.getKey(), (List<String>) entry.getValue());
        }
        for (Map.Entry entry2 : map.entrySet()) {
            builder.addCustomTargeting((String) entry2.getKey(), (String) entry2.getValue());
        }
    }
}
