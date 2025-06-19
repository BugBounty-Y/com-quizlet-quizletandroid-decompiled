package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.braze.Braze;
import com.braze.models.cards.Card;
import com.braze.ui.actions.IAction;
import com.braze.ui.contentcards.listeners.IContentCardsActionListener;
import com.braze.ui.contentcards.managers.BrazeContentCardsManager;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.infra.snackbar.k;
import com.quizlet.features.infra.snackbar.l;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.views.ActivityCenterViewBindingHandler;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityCenterContentCardsFragment extends Hilt_ActivityCenterContentCardsFragment implements IContentCardsActionListener {
    public static final String j;
    public com.quizlet.qutils.image.loading.a g;
    public BrazeContentCardsManager h;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e i = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a.class), new a(this, 0), new a(this, 2), new a(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("ActivityCenterContentCardsFragment", "getSimpleName(...)");
        j = "ActivityCenterContentCardsFragment";
    }

    @Override // com.braze.ui.contentcards.listeners.IContentCardsActionListener
    public final boolean onContentCardClicked(Context context, Card card, IAction iAction) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
        com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a aVar = (com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) this.i.getValue();
        aVar.getClass();
        Intrinsics.checkNotNullParameter(card, "card");
        int iIndexOf = aVar.j.indexOf(card);
        if (iIndexOf >= 0) {
            aVar.h.j(Integer.valueOf(iIndexOf));
        }
        EventLoggerExt.c((EventLogger) aVar.c.c, new com.quizlet.quizletandroid.config.features.properties.d(8));
        if (iAction == null) {
            return false;
        }
        aVar.i.j(Unit.a);
        return false;
    }

    @Override // com.braze.ui.contentcards.listeners.IContentCardsActionListener
    public final void onContentCardDismissed(Context context, Card card) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
        com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a aVar = (com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) this.i.getValue();
        aVar.getClass();
        com.quizlet.features.infra.snackbar.d dVar = k.b;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        aVar.g.j(new l(dVar, -1, new com.quizlet.qutils.string.f(R.string.activity_center_card_dismissed, C4933y.P(args)), null, null, 120));
        ((Braze) aVar.e.b).requestContentCardsRefresh(true);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        BrazeContentCardsManager brazeContentCardsManager = this.h;
        if (brazeContentCardsManager == null) {
            Intrinsics.m("brazeContentManager");
            throw null;
        }
        brazeContentCardsManager.setContentCardsActionListener(this);
        ActivityCenterViewBindingHandler activityCenterViewBindingHandler = new ActivityCenterViewBindingHandler();
        com.quizlet.qutils.image.loading.a imageLoader = this.g;
        if (imageLoader == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        activityCenterViewBindingHandler.b = imageLoader;
        setCustomContentCardsViewBindingHandler(activityCenterViewBindingHandler);
        setCustomContentCardUpdateHandler(((com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) this.i.getValue()).f);
        setDefaultEmptyContentCardsAdapter(new com.quizlet.quizletandroid.ui.activitycenter.adapters.a());
    }

    @Override // com.braze.ui.contentcards.ContentCardsFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        ((com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) this.i.getValue()).h.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new J(this, 27), (byte) 0));
        SwipeRefreshLayout contentCardsSwipeLayout = getContentCardsSwipeLayout();
        if (contentCardsSwipeLayout != null) {
            Context contextRequireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            contentCardsSwipeLayout.setProgressBackgroundColorSchemeColor(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.SysColorCard));
        }
        if (contentCardsSwipeLayout != null) {
            Context contextRequireContext2 = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
            contentCardsSwipeLayout.setColorSchemeColors(com.quizlet.themes.extensions.a.a(contextRequireContext2, R.attr.colorAccent));
        }
        return viewOnCreateView;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        BrazeContentCardsManager brazeContentCardsManager = this.h;
        if (brazeContentCardsManager == null) {
            Intrinsics.m("brazeContentManager");
            throw null;
        }
        brazeContentCardsManager.setContentCardsActionListener(null);
        setCustomContentCardsViewBindingHandler(null);
        setCustomContentCardUpdateHandler(null);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onDestroyView() {
        RecyclerView contentCardsRecyclerView = getContentCardsRecyclerView();
        if (contentCardsRecyclerView != null) {
            contentCardsRecyclerView.setAdapter(null);
        }
        super.onDestroyView();
    }
}
