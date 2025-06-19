package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.ArrayMap;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import androidx.compose.ui.platform.ComposeView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.C1370i;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.b0;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public class OldHomeFragment extends Hilt_OldHomeFragment<b0> implements com.quizlet.quizletandroid.ui.promo.rateus.a, com.quizlet.offline.managers.a, com.quizlet.quizletandroid.ui.live.f {
    public static final String d1;
    public com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L Z;
    public com.google.android.material.snackbar.h c1;
    public com.quizlet.features.setpage.utils.setpermissions.a j;
    public com.quizlet.infra.legacysyncengine.managers.d k;
    public com.quizlet.offline.managers.b l;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c m;
    public androidx.work.impl.model.l n;
    public io.reactivex.rxjava3.core.o o;
    public com.quizlet.quizletandroid.logging.initializer.a p;
    public com.quizlet.quizletandroid.ui.webpages.a q;
    public com.quizlet.quizletandroid.util.d r;
    public com.quizlet.quizletandroid.ui.debug.a s;
    public Y t;
    public CoordinatorLayout y;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e u = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.quizletandroid.ui.globalnav.viewmodel.e.class), new C4728s(this, 3), new C4728s(this, 5), new C4728s(this, 4));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e v = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L.class), new C4728s(this, 6), new C4728s(this, 8), new C4728s(this, 7));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e w = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.features.achievements.notification.f.class), new C4728s(this, 9), new C4728s(this, 11), new C4728s(this, 10));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e x = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.features.achievements.home.a.class), new C4728s(this, 0), new C4728s(this, 2), new C4728s(this, 1));
    public final kotlin.u z = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(21));
    public final kotlin.u A = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(24));
    public final kotlin.u B = kotlin.l.b(new C4699h(this, 10));
    public final kotlin.u C = kotlin.l.b(new C4699h(this, 11));
    public final kotlin.u D = kotlin.l.b(new C4699h(this, 0));
    public final kotlin.u E = kotlin.l.b(new C4699h(this, 1));
    public final kotlin.u F = kotlin.l.b(new C4699h(this, 2));
    public final kotlin.u G = kotlin.l.b(new C4699h(this, 3));
    public final kotlin.u H = kotlin.l.b(new C4699h(this, 4));
    public final kotlin.u I = kotlin.l.b(new C4699h(this, 5));
    public final kotlin.u J = kotlin.l.b(new C4699h(this, 6));
    public final kotlin.u K = kotlin.l.b(new C4699h(this, 7));
    public final ArrayMap L = new ArrayMap();
    public final kotlin.u M = kotlin.l.b(new C4699h(this, 8));
    public final kotlin.u V = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(22));
    public final kotlin.u W = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(23));
    public final kotlin.u X = kotlin.l.b(new C4699h(this, 9));
    public final androidx.recyclerview.widget.W Y = new androidx.recyclerview.widget.W(this, 3);

    static {
        Intrinsics.checkNotNullExpressionValue("OldHomeFragment", "getSimpleName(...)");
        d1 = "OldHomeFragment";
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void A() throws Exception {
        String str = QLiveQrCodeReaderActivity.t;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        startActivityForResult(M5.b(contextRequireContext), 1);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String K() {
        String string = getString(R.string.loggingTag_Home);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return d1;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.old_home_fragment, viewGroup, false);
        int i = R.id.achievementToast;
        AchievementEarnedView achievementEarnedView = (AchievementEarnedView) AbstractC3375o2.c(R.id.achievementToast, viewInflate);
        if (achievementEarnedView != null) {
            i = R.id.home_headless_feed_fragment_container;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.home_headless_feed_fragment_container, viewInflate);
            if (frameLayout != null) {
                i = R.id.home_progress_bar;
                ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.home_progress_bar, viewInflate);
                if (progressBar != null) {
                    i = R.id.homeSnackbarAnchor;
                    CoordinatorLayout coordinatorLayout = (CoordinatorLayout) AbstractC3375o2.c(R.id.homeSnackbarAnchor, viewInflate);
                    if (coordinatorLayout != null) {
                        i = R.id.home_swipe_refresh;
                        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) AbstractC3375o2.c(R.id.home_swipe_refresh, viewInflate);
                        if (swipeRefreshLayout != null) {
                            i = R.id.searchBarView;
                            ComposeView composeView = (ComposeView) AbstractC3375o2.c(R.id.searchBarView, viewInflate);
                            if (composeView != null) {
                                i = R.id.studyBar;
                                if (((ComposeView) AbstractC3375o2.c(R.id.studyBar, viewInflate)) != null) {
                                    i = R.id.unifiedRecyclerView;
                                    RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.unifiedRecyclerView, viewInflate);
                                    if (recyclerView != null) {
                                        b0 b0Var = new b0((ConstraintLayout) viewInflate, achievementEarnedView, frameLayout, progressBar, coordinatorLayout, swipeRefreshLayout, composeView, recyclerView);
                                        Intrinsics.checkNotNullExpressionValue(b0Var, "inflate(...)");
                                        return b0Var;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final boolean P() {
        return true;
    }

    public final void T(int i, com.quizlet.quizletandroid.ui.startpage.nav2.adapters.a aVar) {
        V().a.a(i, aVar);
    }

    public final com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o U() {
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.k;
        if (dVar != null) {
            return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o(y, y, y, dVar);
        }
        Intrinsics.m("loggedInUserManager");
        throw null;
    }

    public final C1370i V() {
        return (C1370i) this.z.getValue();
    }

    public final C1370i W() {
        return (C1370i) this.V.getValue();
    }

    public final RecyclerView X() {
        RecyclerView unifiedRecyclerView = ((b0) J()).h;
        Intrinsics.checkNotNullExpressionValue(unifiedRecyclerView, "unifiedRecyclerView");
        return unifiedRecyclerView;
    }

    public final void Y() {
        if (getView() == null) {
            return;
        }
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y.g.c();
        y.J(true);
        com.quizlet.infra.legacysyncengine.net.f fVar = (com.quizlet.infra.legacysyncengine.net.f) y.r.b;
        fVar.getClass();
        io.reactivex.rxjava3.core.i.o(com.quizlet.infra.legacysyncengine.net.f.i).m(new com.quizlet.infra.legacysyncengine.net.d(fVar, 0), SubsamplingScaleImageView.TILE_SIZE_AUTO).c(new com.quizlet.infra.legacysyncengine.utils.a(io.reactivex.rxjava3.subjects.p.z(), 0));
        Context contextRequireContext = requireContext();
        com.quizlet.quizletandroid.util.d.a(contextRequireContext, contextRequireContext.getString(R.string.refreshing_content));
        SwipeRefreshLayout homeSwipeRefresh = ((b0) J()).f;
        Intrinsics.checkNotNullExpressionValue(homeSwipeRefresh, "homeSwipeRefresh");
        homeSwipeRefresh.setRefreshing(false);
    }

    public final void a0(boolean z) {
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        com.quizlet.quizletandroid.ui.startpage.nav2.model.K k = y.w1;
        if (k != null) {
            y.v1.b(z ? kotlin.collections.A.b(new com.quizlet.quizletandroid.ui.startpage.nav2.model.J(k)) : kotlin.collections.K.a);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 1) {
            String stringExtra = intent != null ? intent.getStringExtra("url_scanned") : null;
            androidx.work.impl.model.l lVar = this.n;
            if (lVar != null) {
                lVar.l(i2, stringExtra);
                return;
            } else {
                Intrinsics.m("livePresenter");
                throw null;
            }
        }
        if (i != 223) {
            return;
        }
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        androidx.lifecycle.X x = y.r1;
        if (i2 == 100) {
            y.v.a("clicked_search", null);
            x.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.e.a);
        } else {
            if (i2 != 300) {
                return;
            }
            x.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.g.a);
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        androidx.fragment.app.I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.m;
        if (cVar == null) {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
        this.t = (Y) D6.f(iRequireActivity, cVar).a(Y.class);
        this.Z = (com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) this.v.getValue();
        androidx.work.impl.model.l lVar = this.n;
        if (lVar == null) {
            Intrinsics.m("livePresenter");
            throw null;
        }
        Intrinsics.checkNotNullParameter(this, "view");
        lVar.c = this;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.y = null;
        X().setAdapter(null);
        V().unregisterAdapterDataObserver(this.Y);
        AchievementEarnedView achievementToast = ((b0) J()).b;
        Intrinsics.checkNotNullExpressionValue(achievementToast, "achievementToast");
        achievementToast.setOnAchievementEventListener(null);
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y.x1.d();
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        this.Z = null;
        super.onDetach();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        requireActivity().setTitle((CharSequence) null);
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        Intrinsics.checkNotNullParameter(this, "rateUsPresenter");
        timber.log.a aVar = timber.log.c.a;
        aVar.g("requesting feed promo from home", new Object[0]);
        ((com.quizlet.quizletandroid.ui.promo.engine.adapters.b) y.u1.getValue()).getClass();
        io.reactivex.rxjava3.core.o requestScheduler = y.d;
        Intrinsics.checkNotNullParameter(requestScheduler, "requestScheduler");
        io.reactivex.rxjava3.core.o mainThreadScheduler = y.e;
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        androidx.work.impl.model.c userProperties = y.f;
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        EventLogger eventLogger = y.h;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        SharedPreferences sharedPreferences = y.i;
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(this, "rateUsManagerPresenter");
        aVar.m("Handle feed promo online", new Object[0]);
        io.reactivex.rxjava3.internal.operators.completable.a aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(5, userProperties.n().e(new com.quizlet.data.repository.explanations.exercise.b(this, sharedPreferences, eventLogger, userProperties)).h(mainThreadScheduler), com.quizlet.quizletandroid.ui.promo.engine.adapters.a.a);
        Intrinsics.checkNotNullExpressionValue(aVar2, "flatMapCompletable(...)");
        io.reactivex.rxjava3.internal.observers.e disposable = aVar2.h(requestScheduler).f(new com.quizlet.background.eventlogging.a(1), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(disposable, "subscribe(...)");
        Intrinsics.checkNotNullParameter(disposable, "subscription");
        com.quizlet.quizletandroid.ui.base.h hVarL = L();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        com.quizlet.baseui.managers.b bVar = hVarL.a;
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = bVar.b.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
        Y y2 = this.t;
        if (y2 != null) {
            kotlinx.coroutines.E.A(p0.j(y2), null, null, new C4752x(y2, false, null), 3);
        } else {
            Intrinsics.m("viewModel");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y.j.a();
        y.k.a(d1);
        com.quizlet.infra.legacysyncengine.net.f fVar = (com.quizlet.infra.legacysyncengine.net.f) y.r.b;
        fVar.getClass();
        io.reactivex.rxjava3.core.i.o(com.quizlet.infra.legacysyncengine.net.f.i).m(new com.quizlet.infra.legacysyncengine.net.d(fVar, 0), SubsamplingScaleImageView.TILE_SIZE_AUTO).c(new com.quizlet.infra.legacysyncengine.utils.a(io.reactivex.rxjava3.subjects.p.z(), 0));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        int i = 8;
        int i2 = 3;
        int i3 = 4;
        int i4 = 0;
        int i5 = 1;
        int i6 = 18;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        this.y = ((b0) J()).e;
        b0 b0Var = (b0) J();
        C4700i c4700i = new C4700i(this, i5);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.L.m(b0Var.e, c4700i);
        b0 b0Var2 = (b0) J();
        b0Var2.g.setContent(new androidx.compose.runtime.internal.d(true, -962343074, new C4703l(this, i5)));
        X().i(new com.quizlet.baserecyclerview.decoration.e(requireContext().getResources().getDimensionPixelSize(R.dimen.listitem_vertical_margin)));
        RecyclerView scrollStateChanges = X();
        Intrinsics.f(scrollStateChanges, "$this$scrollStateChanges");
        io.reactivex.rxjava3.disposables.b bVarU = new com.jakewharton.rxbinding4.recyclerview.c(scrollStateChanges, 1).l(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(this, 5)).u(new C4702k(this, i4), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        H(bVarU);
        RecyclerView childAttachStateChangeEvents = X();
        Intrinsics.f(childAttachStateChangeEvents, "$this$childAttachStateChangeEvents");
        C4887f c4887f = new C4887f(new com.jakewharton.rxbinding4.recyclerview.c(childAttachStateChangeEvents, 0).h(1000L, TimeUnit.MILLISECONDS, io.reactivex.rxjava3.schedulers.e.b), 5);
        io.reactivex.rxjava3.core.o oVar = this.o;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        io.reactivex.rxjava3.internal.operators.observable.W wS = c4887f.s(oVar);
        io.reactivex.rxjava3.core.o oVar2 = this.o;
        if (oVar2 == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        m0 m0VarW = wS.w(oVar2);
        Intrinsics.checkNotNullExpressionValue(m0VarW, "subscribeOn(...)");
        H(B7.d(m0VarW, new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, timber.log.c.a, timber.log.a.class, "i", "i(Ljava/lang/Throwable;)V", 0, 24), new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, this, OldHomeFragment.class, "checkVerticalImpressions", "checkVerticalImpressions()V", 0, 15), null, 4));
        V().registerAdapterDataObserver(this.Y);
        Y y = this.t;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y.r1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i4)));
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new C4725o(this, null), 3);
        Y y2 = this.t;
        if (y2 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y2.d1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 6)));
        Y y3 = this.t;
        if (y3 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y3.e1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 11)));
        Y y4 = this.t;
        if (y4 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y4.h1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 12)));
        Y y5 = this.t;
        if (y5 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y5.f1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 13)));
        Y y6 = this.t;
        if (y6 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y6.i1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 14)));
        Y y7 = this.t;
        if (y7 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y7.j1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 15)));
        Y y8 = this.t;
        if (y8 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y8.k1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 16)));
        Y y9 = this.t;
        if (y9 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y9.l1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 17)));
        Y y10 = this.t;
        if (y10 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y10.m1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i6)));
        Y y11 = this.t;
        if (y11 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y11.n1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 19)));
        Y y12 = this.t;
        if (y12 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y12.o1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 7)));
        Y y13 = this.t;
        if (y13 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y13.g1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i)));
        Y y14 = this.t;
        if (y14 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y14.p1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 9)));
        Y y15 = this.t;
        if (y15 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y15.q1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 10)));
        ProgressBar homeProgressBar = ((b0) J()).d;
        Intrinsics.checkNotNullExpressionValue(homeProgressBar, "homeProgressBar");
        homeProgressBar.setVisibility(0);
        X().setVisibility(8);
        Y y16 = this.t;
        if (y16 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y16.Y.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i5)));
        Y y17 = this.t;
        if (y17 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y17.s1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 2)));
        Y y18 = this.t;
        if (y18 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        y18.t1.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i2)));
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.w;
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).f.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, i3)));
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).g.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(18, new C4701j(this, 5)));
        androidx.lifecycle.J viewLifecycleOwner2 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner2, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner2), null, null, new r(this, null), 3);
        SwipeRefreshLayout homeSwipeRefresh = ((b0) J()).f;
        Intrinsics.checkNotNullExpressionValue(homeSwipeRefresh, "homeSwipeRefresh");
        homeSwipeRefresh.setOnRefreshListener(new C4700i(this, i4));
        AchievementEarnedView achievementToast = ((b0) J()).b;
        Intrinsics.checkNotNullExpressionValue(achievementToast, "achievementToast");
        achievementToast.setOnAchievementEventListener((com.quizlet.features.achievements.notification.f) eVar.getValue());
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).A();
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void s(String gameCode) throws Exception {
        Intrinsics.checkNotNullParameter(gameCode, "gameCode");
        int i = QuizletLiveActivity.z;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        startActivityForResult(AbstractC3721s5.c(contextRequireContext, gameCode), 1);
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void w() throws Exception {
        int i = QuizletLiveActivity.z;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        startActivityForResult(AbstractC3721s5.b(contextRequireContext), 1);
    }
}
