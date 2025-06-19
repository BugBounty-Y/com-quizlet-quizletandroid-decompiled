package com.quizlet.quizletandroid.ui.common.ads.prebid;

import android.os.Handler;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.quizlet.quizletandroid.ui.common.ads.C4634a;
import com.quizlet.quizletandroid.ui.common.ads.C4639f;
import com.quizlet.quizletandroid.ui.common.ads.G;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import org.prebid.mobile.BannerAdUnit;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.bidding.loader.BidLoader;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ C4634a l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ List n;
    public final /* synthetic */ com.google.android.gms.ads.h o;
    public final /* synthetic */ ViewGroup p;
    public final /* synthetic */ WindowManager q;
    public final /* synthetic */ Map r;
    public final /* synthetic */ Map s;
    public final /* synthetic */ Map t;
    public final /* synthetic */ Function0 u;
    public final /* synthetic */ Function1 v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, C4634a c4634a, boolean z, List list, com.google.android.gms.ads.h hVar, ViewGroup viewGroup, WindowManager windowManager, Map map, Map map2, Map map3, Function0 function0, Function1 function1, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = mVar;
        this.l = c4634a;
        this.m = z;
        this.n = list;
        this.o = hVar;
        this.p = viewGroup;
        this.q = windowManager;
        this.r = map;
        this.s = map2;
        this.t = map3;
        this.u = function0;
        this.v = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, this.v, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        m mVar = this.k;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            try {
                C4634a c4634a = this.l;
                if (!c4634a.e) {
                    throw new IllegalStateException("User is not connected to fetch an ad");
                }
                if (!c4634a.c) {
                    throw new IllegalStateException("User is not eligible for ads");
                }
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar = mVar.b;
                com.quizlet.ads.c cVar2 = c4634a.a;
                Map mapC = this.s;
                if (mapC == null) {
                    mapC = V.c();
                }
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b input = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b(cVar2, this.o, this.p, this.q, c4634a, this.r, mapC, new com.quizlet.login.magiclink.ui.e(this.t, 11));
                cVar.getClass();
                Intrinsics.checkNotNullParameter(input, "input");
                final g gVar = (g) cVar.b;
                Intrinsics.checkNotNullParameter(input, "input");
                gVar.d = input;
                ViewGroup viewGroup = input.c;
                viewGroup.removeAllViews();
                u uVar = gVar.f;
                viewGroup.addView((AdManagerAdView) uVar.getValue());
                final boolean zB = input.a.b();
                a callback = new a(gVar, 2);
                ViewGroup viewGroup2 = input.c;
                Intrinsics.checkNotNullParameter(viewGroup2, "<this>");
                Intrinsics.checkNotNullParameter(callback, "callback");
                com.facebook.appevents.m.n(viewGroup2, new G(callback, 4));
                final int i2 = 0;
                Function0 callback2 = new Function0() { // from class: com.quizlet.quizletandroid.ui.common.ads.prebid.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i2) {
                            case 0:
                                if (zB) {
                                    BannerAdUnit bannerAdUnit = (BannerAdUnit) gVar.e.getValue();
                                    bannerAdUnit.getClass();
                                    LogUtil.e(2, "PrebidMobile", "Resuming auto refresh...");
                                    BidLoader bidLoader = bannerAdUnit.b;
                                    if (bidLoader != null) {
                                        bidLoader.c();
                                    }
                                }
                                break;
                            default:
                                if (zB) {
                                    BannerAdUnit bannerAdUnit2 = (BannerAdUnit) gVar.e.getValue();
                                    bannerAdUnit2.getClass();
                                    LogUtil.e(2, "PrebidMobile", "Stopping auto refresh...");
                                    BidLoader bidLoader2 = bannerAdUnit2.b;
                                    if (bidLoader2 != null) {
                                        LogUtil.e(3, "BidLoader", "Cancel refresh timer");
                                        Handler handler = bidLoader2.g.a;
                                        if (handler != null) {
                                            handler.removeCallbacksAndMessages(null);
                                        }
                                    }
                                }
                                break;
                        }
                        return Unit.a;
                    }
                };
                Intrinsics.checkNotNullParameter(viewGroup2, "<this>");
                Intrinsics.checkNotNullParameter(callback2, "callback");
                com.facebook.appevents.m.n(viewGroup2, new G(callback2, 5));
                final int i3 = 1;
                Function0 callback3 = new Function0() { // from class: com.quizlet.quizletandroid.ui.common.ads.prebid.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i3) {
                            case 0:
                                if (zB) {
                                    BannerAdUnit bannerAdUnit = (BannerAdUnit) gVar.e.getValue();
                                    bannerAdUnit.getClass();
                                    LogUtil.e(2, "PrebidMobile", "Resuming auto refresh...");
                                    BidLoader bidLoader = bannerAdUnit.b;
                                    if (bidLoader != null) {
                                        bidLoader.c();
                                    }
                                }
                                break;
                            default:
                                if (zB) {
                                    BannerAdUnit bannerAdUnit2 = (BannerAdUnit) gVar.e.getValue();
                                    bannerAdUnit2.getClass();
                                    LogUtil.e(2, "PrebidMobile", "Stopping auto refresh...");
                                    BidLoader bidLoader2 = bannerAdUnit2.b;
                                    if (bidLoader2 != null) {
                                        LogUtil.e(3, "BidLoader", "Cancel refresh timer");
                                        Handler handler = bidLoader2.g.a;
                                        if (handler != null) {
                                            handler.removeCallbacksAndMessages(null);
                                        }
                                    }
                                }
                                break;
                        }
                        return Unit.a;
                    }
                };
                Intrinsics.checkNotNullParameter(viewGroup2, "<this>");
                Intrinsics.checkNotNullParameter(callback3, "callback");
                com.facebook.appevents.m.n(viewGroup2, new G(callback3, 3));
                AdManagerAdView adManagerAdView = (AdManagerAdView) uVar.getValue();
                com.google.android.gms.ads.d adListener = ((AdManagerAdView) uVar.getValue()).getAdListener();
                Intrinsics.e(adListener, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.common.ads.prebid.PrebidBannerEventListener");
                C4639f c4639f = new C4639f(adManagerAdView, ((n) adListener).b, new com.quizlet.login.common.interactors.d(gVar));
                c4639f.c.i();
                j jVar = new j(this.m, mVar, this.n, this.u, this.v, null);
                this.j = 1;
                if (e0.i(c4639f.b, jVar, this) == aVar) {
                    return aVar;
                }
            } catch (Exception e) {
                if (this.m) {
                    Iterator it2 = this.n.iterator();
                    while (it2.hasNext()) {
                        ((View) it2.next()).setVisibility(8);
                    }
                }
                timber.log.c.a.f(e, "Prebid: Error while validating metadata: " + e, new Object[0]);
                return Unit.a;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
