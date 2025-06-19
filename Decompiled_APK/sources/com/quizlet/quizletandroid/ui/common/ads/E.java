package com.quizlet.quizletandroid.ui.common.ads;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class E implements androidx.lifecycle.I {
    public final com.quizlet.ads.b a;
    public final com.google.mlkit.vision.documentscanner.internal.c b;
    public final I c;
    public final com.quizlet.data.repository.course.membership.c d;
    public final AbstractC5040y e;
    public final AbstractC5040y f;

    public E(com.quizlet.ads.b adTargetsManager, com.google.mlkit.vision.documentscanner.internal.c adBidTargetsProvider, I bannerCreator, com.quizlet.data.repository.course.membership.c adsMetadataCreator, AbstractC5040y mainDispatcher, AbstractC5040y backgroundDispatcher) {
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(adBidTargetsProvider, "adBidTargetsProvider");
        Intrinsics.checkNotNullParameter(bannerCreator, "bannerCreator");
        Intrinsics.checkNotNullParameter(adsMetadataCreator, "adsMetadataCreator");
        Intrinsics.checkNotNullParameter(mainDispatcher, "mainDispatcher");
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        this.a = adTargetsManager;
        this.b = adBidTargetsProvider;
        this.c = bannerCreator;
        this.d = adsMetadataCreator;
        this.e = mainDispatcher;
        this.f = backgroundDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.quizletandroid.ui.common.ads.E r4, int r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.common.ads.l
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.quizletandroid.ui.common.ads.l r0 = (com.quizlet.quizletandroid.ui.common.ads.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.common.ads.l r0 = new com.quizlet.quizletandroid.ui.common.ads.l
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
            com.quizlet.quizletandroid.ui.common.ads.m r7 = new com.quizlet.quizletandroid.ui.common.ads.m
            r2 = 0
            r7.<init>(r4, r5, r6, r2)
            r0.l = r3
            java.lang.Object r4 = com.facebook.appevents.internal.d.b(r7, r0)
            if (r4 != r1) goto L45
            return r1
        L45:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.E.a(com.quizlet.quizletandroid.ui.common.ads.E, int, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
