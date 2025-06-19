package com.quizlet.ads.ui.activity;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.v;
import androidx.compose.foundation.text.z0;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.FragmentContainerView;
import androidx.lifecycle.C;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.ads.AdsNavigationEvent$ShowBannerFragment;
import com.quizlet.ads.AdsNavigationEvent$ShowNativeAdFragment;
import com.quizlet.ads.AdsNavigationEvent$ShowOutStreamVideoFragment;
import com.quizlet.ads.AdsNavigationEvent$ShowVerticalVideoAdFragment;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.ads.data.f;
import com.quizlet.ads.data.h;
import com.quizlet.ads.g;
import com.quizlet.ads.ui.widgets.AdsCountDownButton;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class AdsActivity extends d {
    public static final String u;
    public com.quizlet.quizletandroid.managers.upgrade.a q;
    public g r;
    public androidx.activity.result.b s;
    public final e t;

    static {
        Intrinsics.checkNotNullExpressionValue("AdsActivity", "getSimpleName(...)");
        u = "AdsActivity";
    }

    public AdsActivity() {
        super(0);
        this.t = new e(K.a(com.quizlet.ads.viewmodel.a.class), new b(this, 1), new b(this, 0), new b(this, 2));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return u;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_ads, (ViewGroup) null, false);
        int i = R.id.adsFragmentContainer;
        FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.adsFragmentContainer, viewInflate);
        if (fragmentContainerView != null) {
            i = R.id.countDownButton;
            AdsCountDownButton adsCountDownButton = (AdsCountDownButton) AbstractC3375o2.c(R.id.countDownButton, viewInflate);
            if (adsCountDownButton != null) {
                com.quizlet.ads.databinding.a aVar = new com.quizlet.ads.databinding.a((ConstraintLayout) viewInflate, fragmentContainerView, adsCountDownButton, (FrameLayout) AbstractC3375o2.c(R.id.countDownButtonWrapper, viewInflate));
                Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                return aVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void b0(BaseFragment baseFragment, String str) {
        if (getSupportFragmentManager().E(str) != null) {
            return;
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
        c1121aB.l(((com.quizlet.ads.databinding.a) K()).b.getId(), baseFragment, str);
        c1121aB.g();
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        com.quizlet.ads.viewmodel.a aVar = (com.quizlet.ads.viewmodel.a) this.t.getValue();
        com.quizlet.ads.ui.widgets.d state = ((com.quizlet.ads.databinding.a) K()).c.getState();
        aVar.getClass();
        Intrinsics.checkNotNullParameter(state, "state");
        if (state instanceof com.quizlet.ads.ui.widgets.c) {
            aVar.B();
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        h hVar;
        super.onCreate(bundle);
        v.b(this, null, 3);
        ConstraintLayout constraintLayout = ((com.quizlet.ads.databinding.a) K()).a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        AbstractC3188k6.a(constraintLayout);
        C lifecycle = getLifecycle();
        g gVar = this.r;
        if (gVar == null) {
            Intrinsics.m("adsRepository");
            throw null;
        }
        lifecycle.a(gVar);
        this.s = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.compose.b(this, 1));
        e eVar = this.t;
        com.quizlet.ads.viewmodel.a aVar = (com.quizlet.ads.viewmodel.a) eVar.getValue();
        g gVar2 = this.r;
        if (gVar2 == null) {
            Intrinsics.m("adsRepository");
            throw null;
        }
        if (gVar2.a == null && gVar2.b == null) {
            aVar.B();
        } else {
            Object objA = aVar.c.a("ad_data_extra");
            Intrinsics.e(objA, "null cannot be cast to non-null type com.quizlet.ads.data.AdDataType");
            AdDataType adDataType = (AdDataType) objA;
            boolean z = adDataType instanceof AdDataType.BannerAdType;
            Y y = aVar.j;
            X x = aVar.e;
            if (z) {
                x.j(AdsNavigationEvent$ShowBannerFragment.a);
                aVar.f.j(com.quizlet.ads.data.a.a);
                y.j(new com.quizlet.ads.ui.widgets.c());
            } else {
                if (!(adDataType instanceof AdDataType.CustomAdType)) {
                    throw new NoWhenBranchMatchedException();
                }
                m0 m0Var = aVar.c;
                Object objA2 = m0Var.a("ad_data_extra");
                Intrinsics.e(objA2, "null cannot be cast to non-null type com.quizlet.ads.data.AdDataType");
                int iOrdinal = ((AdDataType) objA2).a.ordinal();
                if (iOrdinal != 0) {
                    Y y2 = aVar.g;
                    if (iOrdinal == 1 || iOrdinal == 2) {
                        x.j(AdsNavigationEvent$ShowNativeAdFragment.a);
                        y2.j(com.quizlet.ads.data.e.a);
                    } else if (iOrdinal == 3) {
                        x.j(AdsNavigationEvent$ShowOutStreamVideoFragment.a);
                        y2.j(new f(((Number) CollectionsKt.f0(com.quizlet.ads.viewmodel.a.l, kotlin.random.e.a)).intValue()));
                        y.j(new com.quizlet.ads.ui.widgets.b());
                    } else {
                        if (iOrdinal != 4 && iOrdinal != 5) {
                            throw new NoWhenBranchMatchedException();
                        }
                        Object objA3 = m0Var.a("ad_data_extra");
                        Intrinsics.e(objA3, "null cannot be cast to non-null type com.quizlet.ads.data.AdDataType");
                        x.j(AdsNavigationEvent$ShowVerticalVideoAdFragment.a);
                        int iOrdinal2 = ((AdDataType) objA3).a.ordinal();
                        if (iOrdinal2 == 4) {
                            hVar = h.a;
                        } else if (iOrdinal2 == 5) {
                            hVar = h.b;
                        }
                        aVar.i.j(hVar);
                        y.j(new com.quizlet.ads.ui.widgets.b());
                    }
                }
            }
        }
        ((com.quizlet.ads.viewmodel.a) eVar.getValue()).e.f(this, new a(0, new z0(1, this, AdsActivity.class, "handleNavigation", "handleNavigation(Lcom/quizlet/ads/AdsNavigationEvent;)V", 0, 6)));
        ((com.quizlet.ads.viewmodel.a) eVar.getValue()).j.f(this, new a(0, new z0(1, this, AdsActivity.class, "setUpCountdownButton", "setUpCountdownButton(Lcom/quizlet/ads/ui/widgets/AdsCountDownButtonState;)V", 0, 7)));
        com.quizlet.ads.databinding.a aVar2 = (com.quizlet.ads.databinding.a) K();
        aVar2.c.setOnClickListener(new com.braze.ui.inappmessage.d(this, 11));
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        g gVar = this.r;
        if (gVar == null) {
            Intrinsics.m("adsRepository");
            throw null;
        }
        if (isChangingConfigurations()) {
            return;
        }
        AdManagerAdView adManagerAdView = gVar.b;
        if (adManagerAdView != null) {
            adManagerAdView.destroy();
        }
        gVar.b = null;
        NativeCustomFormatAd nativeCustomFormatAd = gVar.a;
        if (nativeCustomFormatAd != null) {
            nativeCustomFormatAd.destroy();
        }
        gVar.a = null;
    }
}
