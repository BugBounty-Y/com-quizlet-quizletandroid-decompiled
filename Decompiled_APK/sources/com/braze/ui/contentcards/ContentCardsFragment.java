package com.braze.ui.contentcards;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;
import androidx.fragment.app.Fragment;
import androidx.glance.appwidget.protobuf.Z;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.AbstractC1373j0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.C1386q;
import androidx.recyclerview.widget.L;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.swiperefreshlayout.widget.j;
import com.braze.Braze;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.events.IEventSubscriber;
import com.braze.events.SdkDataWipeEvent;
import com.braze.support.BrazeLogger;
import com.braze.ui.R$color;
import com.braze.ui.R$id;
import com.braze.ui.R$layout;
import com.braze.ui.R$string;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.braze.ui.contentcards.adapters.EmptyContentCardsAdapter;
import com.braze.ui.contentcards.handlers.DefaultContentCardsUpdateHandler;
import com.braze.ui.contentcards.handlers.DefaultContentCardsViewBindingHandler;
import com.braze.ui.contentcards.handlers.IContentCardsUpdateHandler;
import com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler;
import com.braze.ui.contentcards.recycler.ContentCardsDividerItemDecoration;
import com.braze.ui.contentcards.recycler.SimpleItemTouchHelperCallback;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.e;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class ContentCardsFragment extends Fragment implements j {

    @NotNull
    public static final Companion Companion = new Companion(null);
    public ContentCardAdapter cardAdapter;
    private RecyclerView contentCardsRecyclerView;
    private SwipeRefreshLayout contentCardsSwipeLayout;
    private IEventSubscriber<ContentCardsUpdatedEvent> contentCardsUpdatedSubscriber;
    private IContentCardsUpdateHandler customContentCardUpdateHandler;
    private IContentCardsViewBindingHandler customContentCardsViewBindingHandler;
    private InterfaceC5025j0 networkUnavailableJob;
    private IEventSubscriber<SdkDataWipeEvent> sdkDataWipeEventSubscriber;

    @NotNull
    private EmptyContentCardsAdapter defaultEmptyContentCardsAdapter = new EmptyContentCardsAdapter();

    @NotNull
    private final IContentCardsUpdateHandler defaultContentCardUpdateHandler = new DefaultContentCardsUpdateHandler();

    @NotNull
    private final IContentCardsViewBindingHandler defaultContentCardsViewBindingHandler = new DefaultContentCardsViewBindingHandler();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    @e(c = "com.braze.ui.contentcards.ContentCardsFragment$contentCardsUpdate$5", f = "ContentCardsFragment.kt", l = {312}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.contentcards.ContentCardsFragment$contentCardsUpdate$5, reason: invalid class name */
    public static final class AnonymousClass5 extends i implements Function1<h<? super Unit>, Object> {
        int label;

        public AnonymousClass5(h<? super AnonymousClass5> hVar) {
            super(1, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(h<?> hVar) {
            return ContentCardsFragment.this.new AnonymousClass5(hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                ContentCardsFragment contentCardsFragment = ContentCardsFragment.this;
                this.label = 1;
                if (contentCardsFragment.networkUnavailable(this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(h<? super Unit> hVar) {
            return ((AnonymousClass5) create(hVar)).invokeSuspend(Unit.a);
        }
    }

    @Metadata
    @e(c = "com.braze.ui.contentcards.ContentCardsFragment$handleContentCardsUpdatedEvent$1", f = "ContentCardsFragment.kt", l = {272}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.contentcards.ContentCardsFragment$handleContentCardsUpdatedEvent$1, reason: invalid class name */
    public static final class AnonymousClass1 extends i implements Function2<C, h<? super Unit>, Object> {
        final /* synthetic */ ContentCardsUpdatedEvent $event;
        int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass1(ContentCardsUpdatedEvent contentCardsUpdatedEvent, h<? super AnonymousClass1> hVar) {
            super(2, hVar);
            this.$event = contentCardsUpdatedEvent;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(Object obj, h<?> hVar) {
            return ContentCardsFragment.this.new AnonymousClass1(this.$event, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                ContentCardsFragment contentCardsFragment = ContentCardsFragment.this;
                ContentCardsUpdatedEvent contentCardsUpdatedEvent = this.$event;
                this.label = 1;
                if (contentCardsFragment.contentCardsUpdate(contentCardsUpdatedEvent, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(C c, h<? super Unit> hVar) {
            return ((AnonymousClass1) create(c, hVar)).invokeSuspend(Unit.a);
        }
    }

    @Metadata
    @e(c = "com.braze.ui.contentcards.ContentCardsFragment$onRefresh$1", f = "ContentCardsFragment.kt", l = {}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.contentcards.ContentCardsFragment$onRefresh$1, reason: invalid class name and case insensitive filesystem */
    public static final class C15231 extends i implements Function1<h<? super Unit>, Object> {
        int label;

        public C15231(h<? super C15231> hVar) {
            super(1, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(h<?> hVar) {
            return ContentCardsFragment.this.new C15231(hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            SwipeRefreshLayout contentCardsSwipeLayout = ContentCardsFragment.this.getContentCardsSwipeLayout();
            if (contentCardsSwipeLayout != null) {
                contentCardsSwipeLayout.setRefreshing(false);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(h<? super Unit> hVar) {
            return ((C15231) create(hVar)).invokeSuspend(Unit.a);
        }
    }

    @Metadata
    @e(c = "com.braze.ui.contentcards.ContentCardsFragment$onViewStateRestored$1", f = "ContentCardsFragment.kt", l = {}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.contentcards.ContentCardsFragment$onViewStateRestored$1, reason: invalid class name and case insensitive filesystem */
    public static final class C15241 extends i implements Function2<C, h<? super Unit>, Object> {
        final /* synthetic */ Bundle $savedInstanceState;
        int label;
        final /* synthetic */ ContentCardsFragment this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C15241(Bundle bundle, ContentCardsFragment contentCardsFragment, h<? super C15241> hVar) {
            super(2, hVar);
            this.$savedInstanceState = bundle;
            this.this$0 = contentCardsFragment;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(Object obj, h<?> hVar) {
            return new C15241(this.$savedInstanceState, this.this$0, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            ArrayList<String> stringArrayList;
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            Parcelable parcelable = Build.VERSION.SDK_INT >= 33 ? (Parcelable) this.$savedInstanceState.getParcelable("LAYOUT_MANAGER_SAVED_INSTANCE_STATE_KEY", Parcelable.class) : this.$savedInstanceState.getParcelable("LAYOUT_MANAGER_SAVED_INSTANCE_STATE_KEY");
            RecyclerView contentCardsRecyclerView = this.this$0.getContentCardsRecyclerView();
            if (contentCardsRecyclerView != null) {
                AbstractC1381n0 layoutManager = contentCardsRecyclerView.getLayoutManager();
                if (parcelable != null && layoutManager != null) {
                    layoutManager.j0(parcelable);
                }
            }
            ContentCardAdapter contentCardAdapter = this.this$0.cardAdapter;
            if (contentCardAdapter != null && (stringArrayList = this.$savedInstanceState.getStringArrayList("KNOWN_CARD_IMPRESSIONS_SAVED_INSTANCE_STATE_KEY")) != null) {
                contentCardAdapter.setImpressedCardIds(stringArrayList);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(C c, h<? super Unit> hVar) {
            return ((C15241) create(c, hVar)).invokeSuspend(Unit.a);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String contentCardsUpdate$lambda$10(ContentCardsUpdatedEvent contentCardsUpdatedEvent) {
        return "Updating Content Cards views in response to ContentCardsUpdatedEvent: " + contentCardsUpdatedEvent;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String contentCardsUpdate$lambda$11() {
        return "ContentCards received was older than the max time to live of 60 seconds, displaying it for now, but requesting an updated view from the server.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String contentCardsUpdate$lambda$12() {
        return "Old Content Cards was empty, putting up a network spinner and registering the network error message on a delay of 5000 ms.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String networkUnavailable$lambda$16() {
        return "Displaying network unavailable toast.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onPause$lambda$4() {
        return "Invoked com.braze.ui.contentcards.ContentCardsFragment.onPause()";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onResume$lambda$0(ContentCardsFragment contentCardsFragment, ContentCardsUpdatedEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        contentCardsFragment.handleContentCardsUpdatedEvent(event);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onResume$lambda$2(ContentCardsFragment contentCardsFragment, SdkDataWipeEvent it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        contentCardsFragment.handleContentCardsUpdatedEvent(ContentCardsUpdatedEvent.Companion.getEmptyUpdate());
    }

    public final void attachSwipeHelperCallback() {
        ContentCardAdapter contentCardAdapter = this.cardAdapter;
        if (contentCardAdapter != null) {
            new L(new SimpleItemTouchHelperCallback(contentCardAdapter)).f(this.contentCardsRecyclerView);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00c9 A[LOOP:0: B:35:0x00c3->B:37:0x00c9, LOOP_END] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object contentCardsUpdate(@org.jetbrains.annotations.NotNull com.braze.events.ContentCardsUpdatedEvent r11, @org.jetbrains.annotations.NotNull kotlin.coroutines.h<? super kotlin.Unit> r12) {
        /*
            r10 = this;
            r12 = 1
            com.braze.support.BrazeLogger r0 = com.braze.support.BrazeLogger.INSTANCE
            com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.V
            com.braze.requests.framework.o r5 = new com.braze.requests.framework.o
            r1 = 14
            r5.<init>(r11, r1)
            r3 = 0
            r4 = 0
            r6 = 6
            r7 = 0
            r1 = r10
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
            com.braze.ui.contentcards.handlers.IContentCardsUpdateHandler r2 = r10.getContentCardUpdateHandler()
            java.util.List r8 = r2.handleCardUpdate(r11)
            com.braze.ui.contentcards.adapters.ContentCardAdapter r2 = r1.cardAdapter
            if (r2 == 0) goto L23
            r2.replaceCards(r8)
        L23:
            kotlinx.coroutines.j0 r2 = r1.networkUnavailableJob
            r9 = 0
            if (r2 == 0) goto L2b
            r2.j(r9)
        L2b:
            r1.networkUnavailableJob = r9
            boolean r2 = r11.isFromOfflineStorage()
            if (r2 == 0) goto L98
            r2 = 60
            boolean r11 = r11.isTimestampOlderThan(r2)
            if (r11 == 0) goto L98
            com.braze.support.BrazeLogger$Priority r2 = com.braze.support.BrazeLogger.Priority.I
            com.braze.ui.contentcards.b r5 = new com.braze.ui.contentcards.b
            r5.<init>(r12)
            r3 = 0
            r4 = 0
            r6 = 6
            r7 = 0
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
            com.braze.Braze$Companion r11 = com.braze.Braze.Companion
            android.content.Context r2 = r10.requireContext()
            java.lang.String r3 = "requireContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
            com.braze.Braze r11 = r11.getInstance(r2)
            r11.requestContentCardsRefresh()
            boolean r11 = r8.isEmpty()
            if (r11 == 0) goto L98
            androidx.swiperefreshlayout.widget.SwipeRefreshLayout r11 = r1.contentCardsSwipeLayout
            if (r11 == 0) goto L68
            r11.setRefreshing(r12)
        L68:
            com.braze.ui.contentcards.b r5 = new com.braze.ui.contentcards.b
            r11 = 2
            r5.<init>(r11)
            r3 = 0
            r4 = 0
            r2 = 0
            r6 = 7
            r7 = 0
            com.braze.support.BrazeLogger.brazelog$default(r0, r1, r2, r3, r4, r5, r6, r7)
            kotlinx.coroutines.j0 r11 = r1.networkUnavailableJob
            if (r11 == 0) goto L7d
            r11.j(r9)
        L7d:
            com.braze.coroutine.BrazeCoroutineScope r11 = com.braze.coroutine.BrazeCoroutineScope.INSTANCE
            java.lang.Long r12 = new java.lang.Long
            r2 = 5000(0x1388, double:2.4703E-320)
            r12.<init>(r2)
            kotlinx.coroutines.scheduling.e r0 = kotlinx.coroutines.O.a
            kotlinx.coroutines.android.d r0 = kotlinx.coroutines.internal.m.a
            com.braze.ui.contentcards.ContentCardsFragment$contentCardsUpdate$5 r2 = new com.braze.ui.contentcards.ContentCardsFragment$contentCardsUpdate$5
            r2.<init>(r9)
            kotlinx.coroutines.j0 r11 = r11.launchDelayed(r12, r0, r2)
            r1.networkUnavailableJob = r11
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L98:
            if (r8 == 0) goto La1
            boolean r11 = r8.isEmpty()
            if (r11 == 0) goto La1
            goto Lbf
        La1:
            java.util.Iterator r11 = r8.iterator()
        La5:
            boolean r12 = r11.hasNext()
            if (r12 == 0) goto Lbf
            java.lang.Object r12 = r11.next()
            com.braze.models.cards.Card r12 = (com.braze.models.cards.Card) r12
            boolean r12 = r12.isControl()
            if (r12 != 0) goto La5
            com.braze.ui.contentcards.adapters.ContentCardAdapter r11 = r1.cardAdapter
            if (r11 == 0) goto Lda
            r10.swapRecyclerViewAdapter(r11)
            goto Lda
        Lbf:
            java.util.Iterator r11 = r8.iterator()
        Lc3:
            boolean r12 = r11.hasNext()
            if (r12 == 0) goto Ld3
            java.lang.Object r12 = r11.next()
            com.braze.models.cards.Card r12 = (com.braze.models.cards.Card) r12
            r12.logImpression()
            goto Lc3
        Ld3:
            androidx.recyclerview.widget.d0 r11 = r10.getEmptyCardsAdapter()
            r10.swapRecyclerViewAdapter(r11)
        Lda:
            androidx.swiperefreshlayout.widget.SwipeRefreshLayout r11 = r1.contentCardsSwipeLayout
            if (r11 == 0) goto Le2
            r12 = 0
            r11.setRefreshing(r12)
        Le2:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.ui.contentcards.ContentCardsFragment.contentCardsUpdate(com.braze.events.ContentCardsUpdatedEvent, kotlin.coroutines.h):java.lang.Object");
    }

    @NotNull
    public final IContentCardsUpdateHandler getContentCardUpdateHandler() {
        IContentCardsUpdateHandler iContentCardsUpdateHandler = this.customContentCardUpdateHandler;
        return iContentCardsUpdateHandler == null ? this.defaultContentCardUpdateHandler : iContentCardsUpdateHandler;
    }

    public final RecyclerView getContentCardsRecyclerView() {
        return this.contentCardsRecyclerView;
    }

    public final SwipeRefreshLayout getContentCardsSwipeLayout() {
        return this.contentCardsSwipeLayout;
    }

    @NotNull
    public final IContentCardsViewBindingHandler getContentCardsViewBindingHandler() {
        IContentCardsViewBindingHandler iContentCardsViewBindingHandler = this.customContentCardsViewBindingHandler;
        return iContentCardsViewBindingHandler == null ? this.defaultContentCardsViewBindingHandler : iContentCardsViewBindingHandler;
    }

    @NotNull
    public final AbstractC1361d0 getEmptyCardsAdapter() {
        return this.defaultEmptyContentCardsAdapter;
    }

    public final void handleContentCardsUpdatedEvent(@NotNull ContentCardsUpdatedEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        BrazeCoroutineScope brazeCoroutineScope = BrazeCoroutineScope.INSTANCE;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        E.A(brazeCoroutineScope, m.a, null, new AnonymousClass1(event, null), 2);
    }

    public final void initializeRecyclerView() {
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(getActivity());
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        ContentCardAdapter contentCardAdapter = new ContentCardAdapter(contextRequireContext, linearLayoutManager, new ArrayList(), getContentCardsViewBindingHandler());
        this.cardAdapter = contentCardAdapter;
        RecyclerView recyclerView = this.contentCardsRecyclerView;
        if (recyclerView != null) {
            recyclerView.setAdapter(contentCardAdapter);
        }
        RecyclerView recyclerView2 = this.contentCardsRecyclerView;
        if (recyclerView2 != null) {
            recyclerView2.setLayoutManager(linearLayoutManager);
        }
        attachSwipeHelperCallback();
        RecyclerView recyclerView3 = this.contentCardsRecyclerView;
        AbstractC1373j0 itemAnimator = recyclerView3 != null ? recyclerView3.getItemAnimator() : null;
        if (itemAnimator instanceof C1386q) {
            ((C1386q) itemAnimator).g = false;
        }
        RecyclerView recyclerView4 = this.contentCardsRecyclerView;
        if (recyclerView4 != null) {
            Context contextRequireContext2 = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
            recyclerView4.i(new ContentCardsDividerItemDecoration(contextRequireContext2));
        }
    }

    public final Object networkUnavailable(@NotNull h<? super Unit> hVar) {
        Context applicationContext;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new b(3), 6, (Object) null);
        Context context = getContext();
        if (context != null && (applicationContext = context.getApplicationContext()) != null) {
            Toast.makeText(applicationContext, applicationContext.getString(R$string.com_braze_feed_connection_error_title), 1).show();
        }
        swapRecyclerViewAdapter(getEmptyCardsAdapter());
        SwipeRefreshLayout swipeRefreshLayout = this.contentCardsSwipeLayout;
        if (swipeRefreshLayout != null) {
            swipeRefreshLayout.setRefreshing(false);
        }
        return Unit.a;
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(@NotNull LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R$layout.com_braze_content_cards, viewGroup, false);
        this.contentCardsRecyclerView = (RecyclerView) viewInflate.findViewById(R$id.com_braze_content_cards_recycler);
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) viewInflate.findViewById(R$id.braze_content_cards_swipe_container);
        this.contentCardsSwipeLayout = swipeRefreshLayout;
        if (swipeRefreshLayout != null) {
            swipeRefreshLayout.setOnRefreshListener(this);
        }
        SwipeRefreshLayout swipeRefreshLayout2 = this.contentCardsSwipeLayout;
        if (swipeRefreshLayout2 != null) {
            swipeRefreshLayout2.setColorSchemeResources(R$color.com_braze_content_cards_swipe_refresh_color_1, R$color.com_braze_content_cards_swipe_refresh_color_2, R$color.com_braze_content_cards_swipe_refresh_color_3, R$color.com_braze_content_cards_swipe_refresh_color_4);
        }
        return viewInflate;
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new b(0), 6, (Object) null);
        Braze.Companion companion = Braze.Companion;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        companion.getInstance(contextRequireContext).removeSingleSubscription(this.contentCardsUpdatedSubscriber, ContentCardsUpdatedEvent.class);
        Context contextRequireContext2 = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
        companion.getInstance(contextRequireContext2).removeSingleSubscription(this.sdkDataWipeEventSubscriber, SdkDataWipeEvent.class);
        InterfaceC5025j0 interfaceC5025j0 = this.networkUnavailableJob;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        this.networkUnavailableJob = null;
        ContentCardAdapter contentCardAdapter = this.cardAdapter;
        if (contentCardAdapter != null) {
            contentCardAdapter.markOnScreenCardsAsRead();
        }
    }

    @Override // androidx.swiperefreshlayout.widget.j
    public void onRefresh() {
        Braze.Companion companion = Braze.Companion;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        companion.getInstance(contextRequireContext).requestContentCardsRefresh();
        BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, 2500L, null, new C15231(null), 2, null);
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        Braze.Companion companion = Braze.Companion;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        companion.getInstance(contextRequireContext).removeSingleSubscription(this.contentCardsUpdatedSubscriber, ContentCardsUpdatedEvent.class);
        if (this.contentCardsUpdatedSubscriber == null) {
            final int i = 0;
            this.contentCardsUpdatedSubscriber = new IEventSubscriber(this) { // from class: com.braze.ui.contentcards.a
                public final /* synthetic */ ContentCardsFragment b;

                {
                    this.b = this;
                }

                @Override // com.braze.events.IEventSubscriber
                public final void trigger(Object obj) {
                    switch (i) {
                        case 0:
                            ContentCardsFragment.onResume$lambda$0(this.b, (ContentCardsUpdatedEvent) obj);
                            break;
                        default:
                            ContentCardsFragment.onResume$lambda$2(this.b, (SdkDataWipeEvent) obj);
                            break;
                    }
                }
            };
        }
        IEventSubscriber<ContentCardsUpdatedEvent> iEventSubscriber = this.contentCardsUpdatedSubscriber;
        if (iEventSubscriber != null) {
            Context contextRequireContext2 = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
            companion.getInstance(contextRequireContext2).subscribeToContentCardsUpdates(iEventSubscriber);
        }
        Context contextRequireContext3 = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
        companion.getInstance(contextRequireContext3).requestContentCardsRefreshFromCache();
        Context contextRequireContext4 = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
        companion.getInstance(contextRequireContext4).removeSingleSubscription(this.sdkDataWipeEventSubscriber, SdkDataWipeEvent.class);
        if (this.sdkDataWipeEventSubscriber == null) {
            final int i2 = 1;
            this.sdkDataWipeEventSubscriber = new IEventSubscriber(this) { // from class: com.braze.ui.contentcards.a
                public final /* synthetic */ ContentCardsFragment b;

                {
                    this.b = this;
                }

                @Override // com.braze.events.IEventSubscriber
                public final void trigger(Object obj) {
                    switch (i2) {
                        case 0:
                            ContentCardsFragment.onResume$lambda$0(this.b, (ContentCardsUpdatedEvent) obj);
                            break;
                        default:
                            ContentCardsFragment.onResume$lambda$2(this.b, (SdkDataWipeEvent) obj);
                            break;
                    }
                }
            };
        }
        IEventSubscriber<SdkDataWipeEvent> iEventSubscriber2 = this.sdkDataWipeEventSubscriber;
        if (iEventSubscriber2 != null) {
            Context contextRequireContext5 = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
            companion.getInstance(contextRequireContext5).addSingleSynchronousSubscription(iEventSubscriber2, SdkDataWipeEvent.class);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onSaveInstanceState(@NotNull Bundle outState) {
        AbstractC1381n0 layoutManager;
        Intrinsics.checkNotNullParameter(outState, "outState");
        RecyclerView recyclerView = this.contentCardsRecyclerView;
        if (recyclerView != null && (layoutManager = recyclerView.getLayoutManager()) != null) {
            outState.putParcelable("LAYOUT_MANAGER_SAVED_INSTANCE_STATE_KEY", layoutManager.k0());
        }
        ContentCardAdapter contentCardAdapter = this.cardAdapter;
        if (contentCardAdapter != null) {
            outState.putStringArrayList("KNOWN_CARD_IMPRESSIONS_SAVED_INSTANCE_STATE_KEY", new ArrayList<>(contentCardAdapter.getImpressedCardIds()));
        }
        IContentCardsViewBindingHandler iContentCardsViewBindingHandler = this.customContentCardsViewBindingHandler;
        if (iContentCardsViewBindingHandler != null) {
            outState.putParcelable("VIEW_BINDING_HANDLER_SAVED_INSTANCE_STATE_KEY", iContentCardsViewBindingHandler);
        }
        IContentCardsUpdateHandler iContentCardsUpdateHandler = this.customContentCardUpdateHandler;
        if (iContentCardsUpdateHandler != null) {
            outState.putParcelable("UPDATE_HANDLER_SAVED_INSTANCE_STATE_KEY", iContentCardsUpdateHandler);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewStateRestored(Bundle bundle) {
        super.onViewStateRestored(bundle);
        if (bundle != null) {
            int i = Build.VERSION.SDK_INT;
            IContentCardsUpdateHandler iContentCardsUpdateHandler = i >= 33 ? (IContentCardsUpdateHandler) bundle.getParcelable("UPDATE_HANDLER_SAVED_INSTANCE_STATE_KEY", IContentCardsUpdateHandler.class) : (IContentCardsUpdateHandler) bundle.getParcelable("UPDATE_HANDLER_SAVED_INSTANCE_STATE_KEY");
            if (iContentCardsUpdateHandler != null) {
                setContentCardUpdateHandler(iContentCardsUpdateHandler);
            }
            IContentCardsViewBindingHandler iContentCardsViewBindingHandler = i >= 33 ? (IContentCardsViewBindingHandler) bundle.getParcelable("VIEW_BINDING_HANDLER_SAVED_INSTANCE_STATE_KEY", IContentCardsViewBindingHandler.class) : (IContentCardsViewBindingHandler) bundle.getParcelable("VIEW_BINDING_HANDLER_SAVED_INSTANCE_STATE_KEY");
            if (iContentCardsViewBindingHandler != null) {
                setContentCardsViewBindingHandler(iContentCardsViewBindingHandler);
            }
            BrazeCoroutineScope brazeCoroutineScope = BrazeCoroutineScope.INSTANCE;
            kotlinx.coroutines.scheduling.e eVar = O.a;
            E.A(brazeCoroutineScope, m.a, null, new C15241(bundle, this, null), 2);
        }
        initializeRecyclerView();
    }

    public final void setContentCardUpdateHandler(IContentCardsUpdateHandler iContentCardsUpdateHandler) {
        this.customContentCardUpdateHandler = iContentCardsUpdateHandler;
    }

    public final void setContentCardsViewBindingHandler(IContentCardsViewBindingHandler iContentCardsViewBindingHandler) {
        this.customContentCardsViewBindingHandler = iContentCardsViewBindingHandler;
    }

    public final void setCustomContentCardUpdateHandler(IContentCardsUpdateHandler iContentCardsUpdateHandler) {
        this.customContentCardUpdateHandler = iContentCardsUpdateHandler;
    }

    public final void setCustomContentCardsViewBindingHandler(IContentCardsViewBindingHandler iContentCardsViewBindingHandler) {
        this.customContentCardsViewBindingHandler = iContentCardsViewBindingHandler;
    }

    public final void setDefaultEmptyContentCardsAdapter(@NotNull EmptyContentCardsAdapter emptyContentCardsAdapter) {
        Intrinsics.checkNotNullParameter(emptyContentCardsAdapter, "<set-?>");
        this.defaultEmptyContentCardsAdapter = emptyContentCardsAdapter;
    }

    public final void swapRecyclerViewAdapter(@NotNull AbstractC1361d0 newAdapter) {
        Intrinsics.checkNotNullParameter(newAdapter, "newAdapter");
        RecyclerView recyclerView = this.contentCardsRecyclerView;
        if (recyclerView == null || recyclerView.getAdapter() == newAdapter) {
            return;
        }
        recyclerView.setAdapter(newAdapter);
    }
}
