package com.quizlet.ads.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.navigation.C1265a;
import com.quizlet.ads.e;
import com.quizlet.login.common.interactors.d;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.service.j;
import com.quizlet.viewmodel.b;
import io.reactivex.rxjava3.core.o;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class a extends b {
    public static final List k = B.j("ThirdPartyImpressionTrackerMobile", "ThirdPartyImpressionTrackerMobile2", "ThirdPartyImpressionTrackerMobile3");
    public static final List l = B.j(Integer.valueOf(R.string.study_break_copy_1), Integer.valueOf(R.string.study_break_copy_2), Integer.valueOf(R.string.study_break_copy_3), Integer.valueOf(R.string.study_break_copy_4), Integer.valueOf(R.string.study_break_copy_5));
    public final m0 c;
    public final com.quizlet.data.repository.activitycenter.b d;
    public final X e;
    public final Y f;
    public final Y g;
    public final X h;
    public final Y i;
    public final Y j;

    public a(m0 savedStateHandle, com.quizlet.data.repository.activitycenter.b adsTrackingManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(adsTrackingManager, "adsTrackingManager");
        this.c = savedStateHandle;
        this.d = adsTrackingManager;
        this.e = new X(1);
        this.f = new Y();
        Y y = new Y();
        this.g = y;
        this.h = p0.k(y, new C1265a(29));
        this.i = new Y();
        this.j = new Y();
    }

    public final void B() {
        this.e.j(e.a);
        c.a.o("No data on the repository, please check fetcher configuration to populate data", new Object[0]);
    }

    public final void C(ArrayList urls) {
        Intrinsics.checkNotNullParameter(urls, "urls");
        Iterator it2 = urls.iterator();
        while (it2.hasNext()) {
            String url = (String) it2.next();
            com.quizlet.data.repository.activitycenter.b bVar = this.d;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(url, "url");
            d dVar = (d) bVar.b;
            Intrinsics.checkNotNullParameter(url, "url");
            o scheduler = (o) bVar.c;
            Intrinsics.checkNotNullParameter(scheduler, "scheduler");
            ((j) dVar.b).a(url).l(scheduler).h(scheduler).i(com.quizlet.remote.model.logging.a.b, com.quizlet.remote.model.logging.a.c);
        }
    }
}
