package com.quizlet.quizletandroid.ui.common.ads.prebid;

import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.lifecycle.I;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class m implements I {
    public final com.quizlet.ads.b a;
    public final com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c b;
    public final com.quizlet.data.repository.course.membership.c c;
    public final AbstractC5040y d;
    public final AbstractC5040y e;
    public final com.quizlet.data.repository.searchexplanations.c f;

    public m(com.quizlet.ads.b adTargetsManager, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c bannerCreator, com.quizlet.data.repository.course.membership.c adsMetadataCreator, AbstractC5040y mainDispatcher, AbstractC5040y backgroundDispatcher, com.quizlet.data.repository.searchexplanations.c nearestAdSizeMapper) {
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(bannerCreator, "bannerCreator");
        Intrinsics.checkNotNullParameter(adsMetadataCreator, "adsMetadataCreator");
        Intrinsics.checkNotNullParameter(mainDispatcher, "mainDispatcher");
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        Intrinsics.checkNotNullParameter(nearestAdSizeMapper, "nearestAdSizeMapper");
        this.a = adTargetsManager;
        this.b = bannerCreator;
        this.c = adsMetadataCreator;
        this.d = mainDispatcher;
        this.e = backgroundDispatcher;
        this.f = nearestAdSizeMapper;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.quizletandroid.ui.common.ads.prebid.m r4, int r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.common.ads.prebid.h
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.quizletandroid.ui.common.ads.prebid.h r0 = (com.quizlet.quizletandroid.ui.common.ads.prebid.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.common.ads.prebid.h r0 = new com.quizlet.quizletandroid.ui.common.ads.prebid.h
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r4 = r7.a
            return r4
        L2b:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.quizletandroid.ui.common.ads.prebid.i r7 = new com.quizlet.quizletandroid.ui.common.ads.prebid.i
            r2 = 0
            r7.<init>(r4, r5, r6, r2)
            r0.l = r3
            java.lang.Object r4 = com.facebook.appevents.internal.d.b(r7, r0)
            if (r4 != r1) goto L45
            return r1
        L45:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.prebid.m.a(com.quizlet.quizletandroid.ui.common.ads.prebid.m, int, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static Object b(m mVar, int i, String str, ViewGroup viewGroup, WindowManager windowManager, LinkedHashMap linkedHashMap, com.quizlet.features.setpage.composable.a aVar, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l lVar, kotlin.coroutines.jvm.internal.i iVar, int i2) {
        Object objJ = E.J(mVar.e, new l(viewGroup, K.a, mVar, i, (i2 & 2) != 0 ? null : str, windowManager, (i2 & 32) != 0, (i2 & 64) != 0 ? null : linkedHashMap, (i2 & 128) != 0 ? new com.quizlet.login.resetpassword.ui.a(9) : aVar, (i2 & 256) != 0 ? new com.quizlet.quizletandroid.config.features.properties.d(9) : lVar, null), iVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }
}
