package com.braze.ui;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.GestureDetector;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.a0;
import androidx.compose.ui.text.input.C;
import androidx.fragment.app.D0;
import androidx.fragment.app.I;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.swiperefreshlayout.widget.j;
import com.braze.Braze;
import com.braze.enums.CardCategory;
import com.braze.events.FeedUpdatedEvent;
import com.braze.events.IEventSubscriber;
import com.braze.models.cards.Card;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.ui.adapters.BrazeListAdapter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public class BrazeFeedFragment extends D0 implements j {
    private static final String TAG = BrazeLogger.getBrazeLogTag((Class<?>) BrazeFeedFragment.class);
    private BrazeListAdapter mAdapter;
    private EnumSet<CardCategory> mCategories;
    private LinearLayout mEmptyFeedLayout;
    private RelativeLayout mFeedRootLayout;
    private SwipeRefreshLayout mFeedSwipeLayout;
    private IEventSubscriber<FeedUpdatedEvent> mFeedUpdatedSubscriber;
    private GestureDetector mGestureDetector;
    private ProgressBar mLoadingSpinner;
    private LinearLayout mNetworkErrorLayout;
    private View mTransparentFullBoundsContainerView;
    private final Handler mMainThreadLooper = new Handler(Looper.getMainLooper());
    private final Runnable mShowNetworkError = new Runnable() { // from class: com.braze.ui.BrazeFeedFragment.1
        @Override // java.lang.Runnable
        public void run() {
            if (BrazeFeedFragment.this.mLoadingSpinner != null) {
                BrazeFeedFragment.this.mLoadingSpinner.setVisibility(8);
            }
            if (BrazeFeedFragment.this.mNetworkErrorLayout != null) {
                BrazeFeedFragment.this.mNetworkErrorLayout.setVisibility(0);
            }
        }
    };
    private boolean mSortEnabled = false;
    boolean mSkipCardImpressionsReset = false;
    int mPreviousVisibleHeadCardIndex = 0;
    int mCurrentCardIndexAtBottomOfScreen = 0;

    public class FeedGestureListener extends GestureDetector.SimpleOnGestureListener {
        public FeedGestureListener() {
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onDown(MotionEvent motionEvent) {
            return true;
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onFling(MotionEvent motionEvent, MotionEvent motionEvent2, float f, float f2) {
            BrazeFeedFragment.this.getListView().smoothScrollBy(-((int) ((f2 * (2 * r4)) / 1000.0f)), (int) ((motionEvent2.getEventTime() - motionEvent.getEventTime()) * 4));
            return true;
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onScroll(MotionEvent motionEvent, MotionEvent motionEvent2, float f, float f2) {
            BrazeFeedFragment.this.getListView().smoothScrollBy((int) f2, 0);
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onRefresh$5() {
        this.mFeedSwipeLayout.setRefreshing(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean lambda$onViewCreated$0(View view, MotionEvent motionEvent) {
        return this.mGestureDetector.onTouchEvent(motionEvent);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ boolean lambda$onViewCreated$1(View view, MotionEvent motionEvent) {
        return view.getVisibility() == 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onViewCreated$2(FeedUpdatedEvent feedUpdatedEvent, ListView listView) {
        String str = TAG;
        BrazeLogger.v(str, "Updating feed views in response to FeedUpdatedEvent: " + feedUpdatedEvent);
        this.mMainThreadLooper.removeCallbacks(this.mShowNetworkError);
        this.mNetworkErrorLayout.setVisibility(8);
        if (feedUpdatedEvent.getCardCount(this.mCategories) == 0) {
            listView.setVisibility(8);
            this.mAdapter.clear();
        } else {
            this.mEmptyFeedLayout.setVisibility(8);
            this.mLoadingSpinner.setVisibility(8);
            this.mTransparentFullBoundsContainerView.setVisibility(8);
        }
        if (feedUpdatedEvent.isFromOfflineStorage() && (feedUpdatedEvent.lastUpdatedInSecondsFromEpoch() + 60) * 1000 < DateTimeUtils.nowInMilliseconds()) {
            BrazeLogger.i(str, "Feed received was older than the max time to live of 60 seconds, displaying it for now, but requesting an updated view from the server.");
            Braze.getInstance(getContext()).requestFeedRefresh();
            if (feedUpdatedEvent.getCardCount(this.mCategories) == 0) {
                BrazeLogger.d(str, "Old feed was empty, putting up a network spinner and registering the network error message with a delay of 5000ms.");
                this.mEmptyFeedLayout.setVisibility(8);
                this.mLoadingSpinner.setVisibility(0);
                this.mTransparentFullBoundsContainerView.setVisibility(0);
                this.mMainThreadLooper.postDelayed(this.mShowNetworkError, 5000L);
                return;
            }
        }
        if (feedUpdatedEvent.getCardCount(this.mCategories) == 0) {
            this.mLoadingSpinner.setVisibility(8);
            this.mEmptyFeedLayout.setVisibility(0);
            this.mTransparentFullBoundsContainerView.setVisibility(0);
        } else {
            if (!this.mSortEnabled || feedUpdatedEvent.getCardCount(this.mCategories) == feedUpdatedEvent.getUnreadCardCount(this.mCategories)) {
                this.mAdapter.replaceFeed(feedUpdatedEvent.getFeedCards(this.mCategories));
            } else {
                this.mAdapter.replaceFeed(sortFeedCards(feedUpdatedEvent.getFeedCards(this.mCategories)));
            }
            listView.setVisibility(0);
        }
        this.mFeedSwipeLayout.setRefreshing(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onViewCreated$3(ListView listView, FeedUpdatedEvent feedUpdatedEvent) {
        I activity = getActivity();
        if (activity == null) {
            return;
        }
        activity.runOnUiThread(new RunnableC0130g(this, feedUpdatedEvent, listView, 24));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ int lambda$sortFeedCards$4(Card card, Card card2) {
        if (card.isIndicatorHighlighted() == card2.isIndicatorHighlighted()) {
            return 0;
        }
        return card.isIndicatorHighlighted() ? 1 : -1;
    }

    private void setOnScreenCardsToRead() {
        this.mAdapter.batchSetCardsToRead(this.mPreviousVisibleHeadCardIndex, this.mCurrentCardIndexAtBottomOfScreen);
    }

    public void loadFragmentStateFromSavedInstanceState(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        if (this.mCategories == null) {
            this.mCategories = CardCategory.getAllCategories();
        }
        this.mPreviousVisibleHeadCardIndex = bundle.getInt("PREVIOUS_VISIBLE_HEAD_CARD_INDEX", 0);
        this.mCurrentCardIndexAtBottomOfScreen = bundle.getInt("CURRENT_CARD_INDEX_AT_BOTTOM_OF_SCREEN", 0);
        this.mSkipCardImpressionsReset = bundle.getBoolean("SKIP_CARD_IMPRESSIONS_RESET", false);
        ArrayList<String> stringArrayList = bundle.getStringArrayList("CARD_CATEGORY");
        if (stringArrayList != null) {
            this.mCategories.clear();
            Iterator<String> it2 = stringArrayList.iterator();
            while (it2.hasNext()) {
                this.mCategories.add(CardCategory.valueOf(it2.next()));
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        if (this.mAdapter == null) {
            this.mAdapter = new BrazeListAdapter(context, R$id.tag, new ArrayList());
            this.mCategories = CardCategory.getAllCategories();
        }
        this.mGestureDetector = new GestureDetector(context, new FeedGestureListener());
    }

    @Override // androidx.fragment.app.D0, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        View viewInflate = layoutInflater.inflate(R$layout.com_braze_feed, viewGroup, false);
        this.mNetworkErrorLayout = (LinearLayout) viewInflate.findViewById(R$id.com_braze_feed_network_error);
        this.mLoadingSpinner = (ProgressBar) viewInflate.findViewById(R$id.com_braze_feed_loading_spinner);
        this.mEmptyFeedLayout = (LinearLayout) viewInflate.findViewById(R$id.com_braze_feed_empty_feed);
        this.mFeedRootLayout = (RelativeLayout) viewInflate.findViewById(R$id.com_braze_feed_root);
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) viewInflate.findViewById(R$id.braze_feed_swipe_container);
        this.mFeedSwipeLayout = swipeRefreshLayout;
        swipeRefreshLayout.setOnRefreshListener(this);
        this.mFeedSwipeLayout.setEnabled(false);
        this.mFeedSwipeLayout.setColorSchemeResources(R$color.com_braze_newsfeed_swipe_refresh_color_1, R$color.com_braze_newsfeed_swipe_refresh_color_2, R$color.com_braze_newsfeed_swipe_refresh_color_3, R$color.com_braze_newsfeed_swipe_refresh_color_4);
        this.mTransparentFullBoundsContainerView = viewInflate.findViewById(R$id.com_braze_feed_transparent_full_bounds_container_view);
        return viewInflate;
    }

    @Override // androidx.fragment.app.D0, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        Braze.getInstance(getContext()).removeSingleSubscription(this.mFeedUpdatedSubscriber, FeedUpdatedEvent.class);
        setOnScreenCardsToRead();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDetach() {
        super.onDetach();
        setListAdapter(null);
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        setOnScreenCardsToRead();
    }

    @Override // androidx.swiperefreshlayout.widget.j
    public void onRefresh() {
        Braze.getInstance(getContext()).requestFeedRefresh();
        this.mMainThreadLooper.postDelayed(new C(this, 13), 2500L);
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        Braze.getInstance(getContext()).logFeedDisplayed();
    }

    @Override // androidx.fragment.app.Fragment
    public void onSaveInstanceState(Bundle bundle) {
        bundle.putInt("PREVIOUS_VISIBLE_HEAD_CARD_INDEX", this.mPreviousVisibleHeadCardIndex);
        bundle.putInt("CURRENT_CARD_INDEX_AT_BOTTOM_OF_SCREEN", this.mCurrentCardIndexAtBottomOfScreen);
        bundle.putBoolean("SKIP_CARD_IMPRESSIONS_RESET", this.mSkipCardImpressionsReset);
        if (this.mCategories == null) {
            this.mCategories = CardCategory.getAllCategories();
        }
        ArrayList<String> arrayList = new ArrayList<>(this.mCategories.size());
        Iterator<CardCategory> it2 = this.mCategories.iterator();
        while (it2.hasNext()) {
            arrayList.add(it2.next().name());
        }
        bundle.putStringArrayList("CARD_CATEGORY", arrayList);
        if (isVisible()) {
            this.mSkipCardImpressionsReset = true;
        }
    }

    @Override // androidx.fragment.app.D0, androidx.fragment.app.Fragment
    @SuppressLint({"InflateParams"})
    public void onViewCreated(View view, Bundle bundle) {
        super.onViewCreated(view, bundle);
        loadFragmentStateFromSavedInstanceState(bundle);
        if (this.mSkipCardImpressionsReset) {
            this.mSkipCardImpressionsReset = false;
        } else {
            this.mAdapter.resetCardImpressionTracker();
            BrazeLogger.d(TAG, "Resetting card impressions.");
        }
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(getActivity());
        final ListView listView = getListView();
        listView.addHeaderView(layoutInflaterFrom.inflate(R$layout.com_braze_feed_header, (ViewGroup) null));
        listView.addFooterView(layoutInflaterFrom.inflate(R$layout.com_braze_feed_footer, (ViewGroup) null));
        this.mFeedRootLayout.setOnTouchListener(new com.amazon.aps.ads.util.adview.d(this, 1));
        listView.setOnScrollListener(new AbsListView.OnScrollListener() { // from class: com.braze.ui.BrazeFeedFragment.2
            @Override // android.widget.AbsListView.OnScrollListener
            public void onScroll(AbsListView absListView, int i, int i2, int i3) {
                BrazeFeedFragment.this.mFeedSwipeLayout.setEnabled(i == 0);
                if (i2 == 0) {
                    return;
                }
                int i4 = i - 1;
                BrazeFeedFragment brazeFeedFragment = BrazeFeedFragment.this;
                if (i4 > brazeFeedFragment.mPreviousVisibleHeadCardIndex) {
                    brazeFeedFragment.mAdapter.batchSetCardsToRead(BrazeFeedFragment.this.mPreviousVisibleHeadCardIndex, i4);
                }
                BrazeFeedFragment brazeFeedFragment2 = BrazeFeedFragment.this;
                brazeFeedFragment2.mPreviousVisibleHeadCardIndex = i4;
                brazeFeedFragment2.mCurrentCardIndexAtBottomOfScreen = i + i2;
            }

            @Override // android.widget.AbsListView.OnScrollListener
            public void onScrollStateChanged(AbsListView absListView, int i) {
            }
        });
        this.mTransparentFullBoundsContainerView.setOnTouchListener(new a(0));
        Braze.getInstance(getContext()).removeSingleSubscription(this.mFeedUpdatedSubscriber, FeedUpdatedEvent.class);
        this.mFeedUpdatedSubscriber = new IEventSubscriber() { // from class: com.braze.ui.b
            @Override // com.braze.events.IEventSubscriber
            public final void trigger(Object obj) {
                this.a.lambda$onViewCreated$3(listView, (FeedUpdatedEvent) obj);
            }
        };
        Braze.getInstance(getContext()).subscribeToFeedUpdates(this.mFeedUpdatedSubscriber);
        listView.setAdapter((ListAdapter) this.mAdapter);
        Braze.getInstance(getContext()).requestFeedRefreshFromCache();
    }

    public List<Card> sortFeedCards(List<Card> list) {
        Collections.sort(list, new a0(9));
        return list;
    }
}
