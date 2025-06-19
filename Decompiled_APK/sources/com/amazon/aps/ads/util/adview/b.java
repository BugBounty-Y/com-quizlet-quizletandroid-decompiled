package com.amazon.aps.ads.util.adview;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import android.webkit.CookieManager;
import android.webkit.WebView;
import android.widget.ScrollView;
import androidx.compose.ui.platform.C0960p;
import androidx.compose.ui.platform.ViewTreeObserverOnGlobalLayoutListenerC0944h;
import androidx.compose.ui.platform.ViewTreeObserverOnScrollChangedListenerC0946i;
import com.amazon.device.ads.AdRegistration;
import com.amazon.device.ads.DTBActivityListener;
import com.amazon.device.ads.DTBAdMRAIDBannerController;
import com.amazon.device.ads.DTBAdMRAIDController;
import com.amazon.device.ads.DTBAdUtil;
import com.amazon.device.ads.DTBAdViewDisplayListener;
import com.amazon.device.ads.DTBTimeTrace;
import com.amazon.device.ads.DtbOmSdkSessionManager;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class b extends WebView {
    public static final /* synthetic */ int a = 0;
    private boolean adViewScrollEnabled;
    protected com.amazon.aps.ads.model.a apsAdFormat;
    private String bidId;
    protected int exposurePercent;
    protected ViewTreeObserver.OnGlobalFocusChangeListener focusChangeListener;
    protected ViewTreeObserver.OnGlobalLayoutListener globalLayoutListener;
    private String hostname;
    protected boolean ignoreDetachment;
    private boolean isAdViewVisible;
    protected boolean isFirstDisplay;
    private boolean isVideo;
    private DTBAdMRAIDController mraidHandler;
    private com.amazon.aps.ads.metrics.a mraidListenerAdapter;
    private DtbOmSdkSessionManager omSdkManager;
    protected ViewTreeObserver.OnScrollChangedListener scrollChangeListener;
    private long startTime;
    protected long timeClicked;
    protected long timePressed;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.isFirstDisplay = true;
        this.exposurePercent = -1;
        this.adViewScrollEnabled = true;
        CookieManager.getInstance().setAcceptCookie(true);
        this.omSdkManager = DtbOmSdkSessionManager.getNewInstance();
    }

    public static /* synthetic */ void notifyViewabilityAndSetIsVisible$default(b bVar, boolean z, boolean z2, int i, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: notifyViewabilityAndSetIsVisible");
        }
        if ((i & 2) != 0) {
            z2 = false;
        }
        bVar.notifyViewabilityAndSetIsVisible(z, z2);
    }

    public Rect computeAdViewRect(ScrollView scrollView) {
        Intrinsics.checkNotNullParameter(this, "webView");
        Activity activity = DTBAdUtil.getActivity(this);
        if (activity != null) {
            View viewFindViewById = activity.findViewById(R.id.content);
            ViewGroup viewGroup = viewFindViewById instanceof ViewGroup ? (ViewGroup) viewFindViewById : null;
            if (viewGroup != null) {
                int[] iArr = new int[2];
                viewGroup.getLocationInWindow(iArr);
                int i = iArr[0];
                Rect rect = new Rect(i, iArr[1], viewGroup.getWidth() + i, viewGroup.getHeight() + iArr[1]);
                int[] iArr2 = new int[2];
                getLocationInWindow(iArr2);
                int i2 = iArr2[0];
                Rect rect2 = new Rect(i2, iArr2[1], getWidth() + i2, getHeight() + iArr2[1]);
                if (scrollView == null) {
                    rect2.intersect(rect);
                    return rect2;
                }
                int[] iArr3 = new int[2];
                scrollView.getLocationInWindow(iArr3);
                int i3 = iArr3[0];
                Rect rect3 = new Rect(i3, iArr3[1], scrollView.getWidth() + i3, scrollView.getHeight() + iArr3[1]);
                rect3.intersect(rect);
                rect2.intersect(rect3);
                return rect2;
            }
        }
        return null;
    }

    public void computeExposure(boolean z) {
        ScrollView scrollViewParent = getScrollViewParent();
        if (scrollViewParent != null) {
            computeExposureInScrollView(scrollViewParent, z);
            return;
        }
        int[] iArr = new int[2];
        getLocationInWindow(iArr);
        int i = iArr[0];
        Rect rect = new Rect(i, iArr[1], getWidth() + i, getHeight() + iArr[1]);
        if (isMraidHandlerInitialized()) {
            computeExposureInRootView(z);
            onPositionChanged(rect);
        }
    }

    public void computeExposureInRootView(boolean z) {
        Rect rectComputeRootContainerRectInRootView = computeRootContainerRectInRootView();
        if (rectComputeRootContainerRectInRootView == null) {
            return;
        }
        int[] iArr = new int[2];
        getLocationOnScreen(iArr);
        int i = iArr[0];
        Rect rect = new Rect(i, iArr[1], getWidth() + i, getHeight() + iArr[1]);
        float height = getHeight() * getWidth();
        if (!rect.intersect(rectComputeRootContainerRectInRootView)) {
            if (this.exposurePercent != 0 || z) {
                this.exposurePercent = 0;
                rect.top = rect.bottom;
                onExposureChange(0, rect);
                return;
            }
            return;
        }
        int i2 = (int) (((((rect.bottom - rect.top) * (rect.right - rect.left)) * 100.0d) / height) + 0.5d);
        if (i2 != this.exposurePercent || z) {
            this.exposurePercent = i2;
            onExposureChange(i2, rect);
        }
    }

    public int computeExposureInScrollView(@NotNull Rect adViewRect) {
        Intrinsics.checkNotNullParameter(adViewRect, "adViewRect");
        Intrinsics.checkNotNullParameter(this, "webView");
        Intrinsics.checkNotNullParameter(adViewRect, "adViewRect");
        float height = getHeight() * getWidth();
        float f = (adViewRect.bottom - adViewRect.top) * (adViewRect.right - adViewRect.left);
        if (height == DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        return (int) ((100 * f) / height);
    }

    public Rect computeRootContainerRectInRootView() {
        Intrinsics.checkNotNullParameter(this, "webView");
        Object parent = getParent();
        View view = parent instanceof View ? (View) parent : null;
        Activity activity = view != null ? DTBAdUtil.getActivity(view) : DTBAdUtil.getActivity(this);
        if (activity != null) {
            View viewFindViewById = activity.findViewById(R.id.content);
            ViewGroup viewGroup = viewFindViewById instanceof ViewGroup ? (ViewGroup) viewFindViewById : null;
            if (viewGroup != null) {
                int[] iArr = new int[2];
                viewGroup.getLocationInWindow(iArr);
                int i = iArr[0];
                return new Rect(i, iArr[1], viewGroup.getWidth() + i, viewGroup.getHeight() + iArr[1]);
            }
        }
        return null;
    }

    public void finalize() {
        try {
            ViewTreeObserver viewTreeObserver = getViewTreeObserver();
            if (viewTreeObserver == null) {
                return;
            }
            viewTreeObserver.removeOnGlobalLayoutListener(this.globalLayoutListener);
            viewTreeObserver.removeOnScrollChangedListener(this.scrollChangeListener);
            viewTreeObserver.removeOnGlobalFocusChangeListener(this.focusChangeListener);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute finalize method", e);
        }
    }

    public final boolean getAdViewScrollEnabled() {
        return this.adViewScrollEnabled;
    }

    public final String getBidId() {
        return this.bidId;
    }

    public final String getHostname() {
        return this.hostname;
    }

    public final DTBAdMRAIDController getMraidHandler() {
        return this.mraidHandler;
    }

    public final com.amazon.aps.ads.metrics.a getMraidListenerAdapter() {
        return this.mraidListenerAdapter;
    }

    public final DtbOmSdkSessionManager getOmSdkManager() {
        return this.omSdkManager;
    }

    public final ScrollView getScrollViewParent() {
        Intrinsics.checkNotNullParameter(this, "webView");
        ViewGroup viewGroup = this;
        do {
            ViewParent parent = viewGroup.getParent();
            viewGroup = parent instanceof ViewGroup ? (ViewGroup) parent : null;
            if (viewGroup == null) {
                return null;
            }
        } while (!(viewGroup instanceof ScrollView));
        return (ScrollView) viewGroup;
    }

    public final long getStartTime() {
        return this.startTime;
    }

    public final void initLayoutListeners() {
        this.globalLayoutListener = new ViewTreeObserverOnGlobalLayoutListenerC0944h(this, 1);
        this.focusChangeListener = new ViewTreeObserver.OnGlobalFocusChangeListener() { // from class: com.amazon.aps.ads.util.adview.a
            @Override // android.view.ViewTreeObserver.OnGlobalFocusChangeListener
            public final void onGlobalFocusChanged(View view, View view2) {
                int i = b.a;
                b this$0 = this.a;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.verifyIsVisible();
            }
        };
        this.scrollChangeListener = new ViewTreeObserverOnScrollChangedListenerC0946i(this, 1);
    }

    public final boolean isAdViewVisible() {
        return this.isAdViewVisible;
    }

    public boolean isMraidHandlerInitialized() {
        return this.mraidHandler != null;
    }

    public final boolean isVideo() {
        return this.isVideo;
    }

    public void notifyViewabilityAndSetIsVisible(boolean z, boolean z2) {
        if (this.isAdViewVisible || z2) {
            if (isMraidHandlerInitialized()) {
                onViewabilityChanged(z);
            }
            setAdViewVisible(z);
        }
    }

    public abstract void onAdOpened();

    @Override // android.webkit.WebView, android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        try {
            super.onAttachedToWindow();
            ViewTreeObserver viewTreeObserver = getViewTreeObserver();
            if (viewTreeObserver != null) {
                viewTreeObserver.addOnGlobalLayoutListener(this.globalLayoutListener);
                viewTreeObserver.addOnGlobalFocusChangeListener(this.focusChangeListener);
                viewTreeObserver.addOnScrollChangedListener(this.scrollChangeListener);
            }
            if (isMraidHandlerInitialized()) {
                onAdOpened();
            }
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute onAttachedToWindow method", e);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        DtbOmSdkSessionManager omSdkManager;
        try {
            super.onDetachedFromWindow();
            ViewTreeObserver viewTreeObserver = getViewTreeObserver();
            if (viewTreeObserver != null) {
                viewTreeObserver.removeOnGlobalLayoutListener(this.globalLayoutListener);
                viewTreeObserver.removeOnScrollChangedListener(this.scrollChangeListener);
                viewTreeObserver.removeOnGlobalFocusChangeListener(this.focusChangeListener);
            }
            DTBAdMRAIDController dTBAdMRAIDController = this.mraidHandler;
            if (dTBAdMRAIDController != null && (dTBAdMRAIDController instanceof DTBAdMRAIDBannerController) && getOmSdkManager() != null && (omSdkManager = getOmSdkManager()) != null) {
                omSdkManager.stopOmAdSession();
            }
            this.mraidListenerAdapter = null;
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute onDetachedFromWindow method in ApsAdView class", e);
        }
    }

    @Override // android.webkit.WebView, android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.isFirstDisplay) {
            DTBTimeTrace dTBTimeTrace = DTBTimeTrace.getInstance();
            if (dTBTimeTrace != null && AdRegistration.isTestMode()) {
                dTBTimeTrace.addPhase(DTBTimeTrace.TIMETRACE_AD_DISPLAY_SUCCEEDED);
                dTBTimeTrace.logTrace();
            }
            DTBActivityListener dTBActivityListener = this.mraidHandler;
            if (dTBActivityListener instanceof DTBAdViewDisplayListener) {
                if (dTBActivityListener == null) {
                    throw new NullPointerException("null cannot be cast to non-null type com.amazon.device.ads.DTBAdViewDisplayListener");
                }
                ((DTBAdViewDisplayListener) dTBActivityListener).onInitialDisplay();
            }
            this.isFirstDisplay = false;
        }
    }

    public abstract void onExposureChange(int i, Rect rect);

    public abstract void onPositionChanged(Rect rect);

    @Override // android.webkit.WebView, android.view.View
    public void onScrollChanged(int i, int i2, int i3, int i4) {
        if (this.adViewScrollEnabled) {
            super.onScrollChanged(i, i2, i4, i3);
        } else {
            scrollTo(0, 0);
        }
    }

    public abstract void onViewabilityChanged(boolean z);

    public final void setAdViewScrollEnabled(boolean z) {
        this.adViewScrollEnabled = z;
        setVerticalScrollBarEnabled(z);
        setHorizontalScrollBarEnabled(z);
    }

    public final void setAdViewVisible(boolean z) {
        this.isAdViewVisible = z;
        if (z) {
            return;
        }
        this.exposurePercent = -1;
        if (isMraidHandlerInitialized()) {
            onExposureChange(0, new Rect(0, 0, 0, 0));
        }
    }

    public final void setBidId(String str) {
        this.bidId = str;
        com.amazon.aps.ads.metrics.a aVar = this.mraidListenerAdapter;
        if (aVar == null) {
            return;
        }
        aVar.c(str);
    }

    public abstract void setCurrentPositionProperty();

    public final void setHostname(String str) {
        this.hostname = str;
    }

    public final void setMraidHandler(DTBAdMRAIDController dTBAdMRAIDController) {
        this.mraidHandler = dTBAdMRAIDController;
    }

    public final void setMraidListenerAdapter(com.amazon.aps.ads.metrics.a aVar) {
        this.mraidListenerAdapter = aVar;
    }

    public void setScrollEnabled(boolean z) {
        setAdViewScrollEnabled(z);
        setVerticalScrollBarEnabled(z);
        setHorizontalScrollBarEnabled(z);
    }

    public final void setStartTime(long j) {
        this.startTime = j;
    }

    public final void setVideo(boolean z) {
        this.isVideo = z;
    }

    public void verifyIsVisible() {
        ViewGroup viewGroup;
        AbstractC3538u.a(this, Intrinsics.k(Boolean.valueOf(this.isAdViewVisible), "method verifyIsVisible called: "));
        com.quizlet.shared.usecase.folderstudymaterials.a aVar = c.b;
        boolean z = this.isAdViewVisible;
        C0960p notifyViewabilityAndSetIsVisible = new C0960p(2, this, b.class, "notifyViewabilityAndSetIsVisible", "notifyViewabilityAndSetIsVisible(ZZ)V", 0, 3);
        Intrinsics.checkNotNullParameter(this, "webView");
        Intrinsics.checkNotNullParameter(notifyViewabilityAndSetIsVisible, "notifyViewabilityAndSetIsVisible");
        if (getParent() == null || getVisibility() != 0) {
            Boolean bool = Boolean.FALSE;
            notifyViewabilityAndSetIsVisible.invoke(bool, bool);
        } else {
            Activity currentActivity = AdRegistration.getCurrentActivity();
            if (currentActivity == null) {
                Boolean bool2 = Boolean.FALSE;
                notifyViewabilityAndSetIsVisible.invoke(bool2, bool2);
            } else {
                try {
                    viewGroup = (ViewGroup) currentActivity.findViewById(R.id.content);
                } catch (RuntimeException e) {
                    Intrinsics.checkNotNullParameter(aVar, "<this>");
                    com.amazon.aps.shared.a.e(1, 1, "Fail to get content view", e);
                    viewGroup = null;
                }
                if (viewGroup == null) {
                    Boolean bool3 = Boolean.FALSE;
                    notifyViewabilityAndSetIsVisible.invoke(bool3, bool3);
                } else {
                    int[] iArr = new int[2];
                    viewGroup.getLocationInWindow(iArr);
                    int i = iArr[0];
                    Rect rect = new Rect(i, iArr[1], viewGroup.getWidth() + i, viewGroup.getHeight() + iArr[1]);
                    int[] iArr2 = new int[2];
                    getLocationInWindow(iArr2);
                    int i2 = iArr2[0];
                    Rect rect2 = new Rect(i2, iArr2[1], getWidth() + i2, getHeight() + iArr2[1]);
                    if (rect.contains(rect2) || Rect.intersects(rect, rect2)) {
                        ScrollView scrollViewParent = getScrollViewParent();
                        if (scrollViewParent != null) {
                            int[] iArr3 = new int[2];
                            scrollViewParent.getLocationInWindow(iArr3);
                            int i3 = iArr3[0];
                            Rect rect3 = new Rect(i3, iArr3[1], scrollViewParent.getWidth() + i3, scrollViewParent.getHeight() + iArr3[1]);
                            if (!Rect.intersects(rect2, rect3)) {
                                notifyViewabilityAndSetIsVisible.invoke(Boolean.FALSE, Boolean.TRUE);
                                AbstractC3538u.a(aVar, "SET MRAID Visible false because of scroll ");
                            } else if (Rect.intersects(rect2, rect3) && !z) {
                                notifyViewabilityAndSetIsVisible.invoke(Boolean.TRUE, Boolean.valueOf(!z));
                                AbstractC3538u.a(aVar, "SET MRAID Visible true because of scroll ");
                            }
                        } else {
                            notifyViewabilityAndSetIsVisible.invoke(Boolean.TRUE, Boolean.valueOf(!z));
                        }
                    } else {
                        Boolean bool4 = Boolean.FALSE;
                        notifyViewabilityAndSetIsVisible.invoke(bool4, bool4);
                    }
                }
            }
        }
        if (this.isAdViewVisible) {
            computeExposure(false);
        }
    }

    public void computeExposureInScrollView(ScrollView scrollView, boolean z) {
        Rect rectComputeAdViewRect = computeAdViewRect(scrollView);
        if (rectComputeAdViewRect == null) {
            return;
        }
        int iComputeExposureInScrollView = computeExposureInScrollView(rectComputeAdViewRect);
        if (iComputeExposureInScrollView != this.exposurePercent || z) {
            this.exposurePercent = iComputeExposureInScrollView;
            onExposureChange(iComputeExposureInScrollView, rectComputeAdViewRect);
            setCurrentPositionProperty();
        }
    }
}
