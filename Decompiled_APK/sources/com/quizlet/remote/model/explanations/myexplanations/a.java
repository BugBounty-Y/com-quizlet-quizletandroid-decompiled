package com.quizlet.remote.model.explanations.myexplanations;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.quizletandroid.ui.common.adapter.c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.myexplanations.RecentExplanationsResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ C1721Kc a;

    public a(C1721Kc c1721Kc) {
        this.a = c1721Kc;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list;
        List list2;
        List list3;
        ApiThreeWrapper wrapper = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(wrapper, "wrapper");
        RecentExplanationsResponse recentExplanationsResponse = (RecentExplanationsResponse) wrapper.a();
        RecentExplanationsResponse.Models models = recentExplanationsResponse != null ? recentExplanationsResponse.d : null;
        C1721Kc c1721Kc = this.a;
        return CollectionsKt.c0(CollectionsKt.c0((models == null || (list3 = models.b) == null) ? K.a : S.f((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a) c1721Kc.c, list3), (models == null || (list2 = models.a) == null) ? K.a : S.f((com.quizlet.quizletandroid.managers.upgrade.a) c1721Kc.d, list2)), (models == null || (list = models.c) == null) ? K.a : S.f((c) c1721Kc.e, list));
    }
}
