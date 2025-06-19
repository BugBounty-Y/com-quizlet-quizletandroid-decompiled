package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.view.WindowManager;
import android.widget.FrameLayout;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.I;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N4;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.E;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ MatchStartGameFragment l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(boolean z, MatchStartGameFragment matchStartGameFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = matchStartGameFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        I i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i2 = this.j;
        if (i2 == 0) {
            Z.e(obj);
            boolean z = this.k;
            MatchStartGameFragment matchStartGameFragment = this.l;
            if (z) {
                i = matchStartGameFragment.k;
                if (i == null) {
                    Intrinsics.m("prebidAdaptiveBannerAdViewHelper");
                    throw null;
                }
            } else {
                i = matchStartGameFragment.j;
                if (i == null) {
                    Intrinsics.m("adaptiveBannerAdViewHelperProvider");
                    throw null;
                }
            }
            matchStartGameFragment.getViewLifecycleOwner().getLifecycle().a(i);
            if (z) {
                com.quizlet.quizletandroid.ui.common.ads.prebid.m mVar = matchStartGameFragment.k;
                if (mVar == null) {
                    Intrinsics.m("prebidAdaptiveBannerAdViewHelper");
                    throw null;
                }
                FrameLayout floatingAdContainer = ((com.quizlet.quizletandroid.databinding.C) matchStartGameFragment.J()).b;
                Intrinsics.checkNotNullExpressionValue(floatingAdContainer, "floatingAdContainer");
                WindowManager windowManager = matchStartGameFragment.requireActivity().getWindowManager();
                Intrinsics.checkNotNullExpressionValue(windowManager, "getWindowManager(...)");
                this.j = 1;
                if (com.quizlet.quizletandroid.ui.common.ads.prebid.m.b(mVar, R.string.match_mode_ad_unit_AndroidMatch320x50, null, floatingAdContainer, windowManager, null, null, null, this, 498) == aVar) {
                    return aVar;
                }
            } else {
                E e = matchStartGameFragment.j;
                if (e == null) {
                    Intrinsics.m("adaptiveBannerAdViewHelperProvider");
                    throw null;
                }
                FrameLayout floatingAdContainer2 = ((com.quizlet.quizletandroid.databinding.C) matchStartGameFragment.J()).b;
                Intrinsics.checkNotNullExpressionValue(floatingAdContainer2, "floatingAdContainer");
                WindowManager windowManager2 = matchStartGameFragment.requireActivity().getWindowManager();
                Intrinsics.checkNotNullExpressionValue(windowManager2, "getWindowManager(...)");
                J0 j0A = N4.a(e, R.string.match_mode_ad_unit_AndroidMatch320x50, null, floatingAdContainer2, windowManager2, null, 114);
                J viewLifecycleOwner = matchStartGameFragment.getViewLifecycleOwner();
                Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
                e0.w(j0A, p0.h(viewLifecycleOwner));
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
