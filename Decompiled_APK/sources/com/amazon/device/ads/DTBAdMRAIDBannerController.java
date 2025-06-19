package com.amazon.device.ads;

import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.LinearLayout;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public class DTBAdMRAIDBannerController extends DTBAdMRAIDController implements DTBMRAIDCloseButtonListener {
    private static final int ANIMATION_DURATION = 500;
    private static List<WeakReference<DTBAdMRAIDBannerController>> bannerControllers = new ArrayList();
    private static AtomicInteger indexDispencer = new AtomicInteger(100);
    private ObjectAnimator animater;
    private float animationProgress;
    public DTBAdBannerListener bannerListener;
    private ViewGroup defaultParent;
    private AnimationPoint endAnimation;
    private ViewGroup expandedBackground;
    private int index;
    private int originalHeight;
    private ViewGroup.LayoutParams originalParams;
    private int originalWidth;
    private float originalX;
    private int originalXPos;
    private float originalY;
    private int originalYPos;
    private AnimationPoint startAnimation;

    public class AnimationPoint {
        int height;
        int width;
        int xPos;
        int yPos;

        public AnimationPoint(int i, int i2, int i3, int i4) {
            this.xPos = i;
            this.yPos = i2;
            this.width = i3;
            this.height = i4;
        }
    }

    public class BackgroundView extends LinearLayout {
        public BackgroundView(Context context) {
            super(context);
            setOrientation(1);
        }
    }

    public class ExpandedBannerListener implements DTBAdExpandedListener {
        public ExpandedBannerListener() {
        }

        @Override // com.amazon.device.ads.DTBAdExpandedListener
        public void onAdLoaded(DTBAdView dTBAdView) {
        }

        @Override // com.amazon.device.ads.DTBAdExpandedListener
        public void onCreateExpandedController(DTBAdMRAIDExpandedController dTBAdMRAIDExpandedController) {
            dTBAdMRAIDExpandedController.setMasterController(DTBAdMRAIDBannerController.this);
        }
    }

    public DTBAdMRAIDBannerController(DTBAdView dTBAdView, DTBAdBannerListener dTBAdBannerListener) {
        super(dTBAdView);
        this.index = indexDispencer.incrementAndGet();
        this.bannerListener = dTBAdBannerListener;
        this.customButtonListener = this;
    }

    private void executeOnePartExpand(Map<String, Object> map) {
        int i;
        int i2;
        final boolean zBooleanValue;
        int iIntValue;
        int iIntValue2;
        this.originalX = getAdView().getX();
        this.originalY = getAdView().getY();
        ViewGroup rootView = DTBAdUtil.getRootView(getAdView());
        if (rootView == null) {
            fireErrorEvent("expand", "rootview doesn't exist in one part expand");
            commandCompleted("expand");
            return;
        }
        int[] iArr = new int[2];
        getAdView().getLocationInWindow(iArr);
        this.defaultParent = (ViewGroup) getAdView().getParent();
        this.originalParams = getAdView().getLayoutParams();
        getAdView().setIgnoreDetachment();
        this.defaultParent.removeView(getAdView());
        int[] iArr2 = new int[2];
        rootView.getLocationInWindow(iArr2);
        int height = rootView.getHeight();
        final int width = rootView.getWidth();
        this.startAnimation = new AnimationPoint(iArr[0] - iArr2[0], iArr[1] - iArr2[1], getAdView().getWidth(), getAdView().getHeight());
        if (map.containsKey("position") && (map.get("position") instanceof Map)) {
            Map map2 = (Map) map.get("position");
            int iSizeToDevicePixels = (!map2.containsKey(OTUXParamsKeys.OT_UX_WIDTH) || (iIntValue2 = ((Integer) map2.get(OTUXParamsKeys.OT_UX_WIDTH)).intValue()) <= 0) ? width : DTBAdUtil.sizeToDevicePixels(iIntValue2);
            if (map2.containsKey(OTUXParamsKeys.OT_UX_HEIGHT) && (iIntValue = ((Integer) map2.get(OTUXParamsKeys.OT_UX_HEIGHT)).intValue()) > 0) {
                height = DTBAdUtil.sizeToDevicePixels(iIntValue);
            }
            if (map2.containsKey("useCustomClose")) {
                zBooleanValue = ((Boolean) map2.get("useCustomClose")).booleanValue();
                i2 = iSizeToDevicePixels;
                i = height;
                BackgroundView backgroundView = new BackgroundView(getAdView().getContext());
                this.expandedBackground = backgroundView;
                backgroundView.setBackgroundColor(0);
                rootView.addView(backgroundView, -1, -1);
                ViewGroup.MarginLayoutParams marginLayoutParams = new ViewGroup.MarginLayoutParams(getAdView().getWidth(), getAdView().getHeight());
                AnimationPoint animationPoint = this.startAnimation;
                marginLayoutParams.leftMargin = animationPoint.xPos;
                marginLayoutParams.topMargin = animationPoint.yPos;
                rootView.bringChildToFront(backgroundView);
                backgroundView.addView(getAdView(), marginLayoutParams);
                getAdView().setX(this.startAnimation.xPos);
                getAdView().setY(this.startAnimation.yPos);
                this.endAnimation = new AnimationPoint(0, 0, i2, i);
                setCurrentPositionProperty(DTBAdUtil.pixelsToDeviceIndependenPixels(i2), DTBAdUtil.pixelsToDeviceIndependenPixels(i));
                ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "animationProgress", DefinitionKt.NO_Float_VALUE, 1.0f);
                this.animater = objectAnimatorOfFloat;
                objectAnimatorOfFloat.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.amazon.device.ads.f
                    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                        this.a.lambda$executeOnePartExpand$8(width, zBooleanValue, valueAnimator);
                    }
                });
                this.animater.setDuration(500L);
                this.animater.start();
            }
            i2 = iSizeToDevicePixels;
            i = height;
        } else {
            i = height;
            i2 = width;
        }
        zBooleanValue = false;
        BackgroundView backgroundView2 = new BackgroundView(getAdView().getContext());
        this.expandedBackground = backgroundView2;
        backgroundView2.setBackgroundColor(0);
        rootView.addView(backgroundView2, -1, -1);
        ViewGroup.MarginLayoutParams marginLayoutParams2 = new ViewGroup.MarginLayoutParams(getAdView().getWidth(), getAdView().getHeight());
        AnimationPoint animationPoint2 = this.startAnimation;
        marginLayoutParams2.leftMargin = animationPoint2.xPos;
        marginLayoutParams2.topMargin = animationPoint2.yPos;
        rootView.bringChildToFront(backgroundView2);
        backgroundView2.addView(getAdView(), marginLayoutParams2);
        getAdView().setX(this.startAnimation.xPos);
        getAdView().setY(this.startAnimation.yPos);
        this.endAnimation = new AnimationPoint(0, 0, i2, i);
        setCurrentPositionProperty(DTBAdUtil.pixelsToDeviceIndependenPixels(i2), DTBAdUtil.pixelsToDeviceIndependenPixels(i));
        ObjectAnimator objectAnimatorOfFloat2 = ObjectAnimator.ofFloat(this, "animationProgress", DefinitionKt.NO_Float_VALUE, 1.0f);
        this.animater = objectAnimatorOfFloat2;
        objectAnimatorOfFloat2.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.amazon.device.ads.f
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                this.a.lambda$executeOnePartExpand$8(width, zBooleanValue, valueAnimator);
            }
        });
        this.animater.setDuration(500L);
        this.animater.start();
    }

    private void executeTwoPartsExpand(Map<String, Object> map) {
        String str = (String) map.get(DTBMetricsConfiguration.APSMETRICS_URL);
        Activity activity = DTBAdUtil.getActivity(getAdView());
        Intent intent = new Intent(activity, (Class<?>) DTBAdActivity.class);
        if (str != null) {
            intent.putExtra(DTBMetricsConfiguration.APSMETRICS_URL, str);
        }
        intent.putExtra("ad_state", "expanded");
        intent.putExtra("cntrl_index", this.index);
        intent.putExtra("two_part_expand", true);
        if (map.get(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY) != null) {
            intent.putExtra(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY, (Serializable) map.get(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY));
        }
        activity.startActivity(intent);
        commandCompleted("expand");
        setState(MraidStateType.EXPANDED);
        bannerControllers.add(new WeakReference<>(this));
    }

    public static DTBAdMRAIDBannerController findControllerByIndex(int i) {
        Iterator<WeakReference<DTBAdMRAIDBannerController>> it2 = bannerControllers.iterator();
        while (it2.hasNext()) {
            DTBAdMRAIDBannerController dTBAdMRAIDBannerController = it2.next().get();
            if (dTBAdMRAIDBannerController != null && dTBAdMRAIDBannerController.index == i) {
                return dTBAdMRAIDBannerController;
            }
        }
        return null;
    }

    private boolean isVisibleRecyclerOrListView(ViewParent viewParent) {
        if (viewParent == null) {
            return false;
        }
        if (viewParent.toString().toLowerCase().contains("recyclerview") || viewParent.toString().toLowerCase().contains("listview")) {
            return true;
        }
        return isVisibleRecyclerOrListView(viewParent.getParent());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$executeOnePartExpand$8(int i, boolean z, ValueAnimator valueAnimator) {
        if (updateAdViewLayout(valueAnimator).floatValue() == 1.0f) {
            addCloseIndicator(i, 0, z);
            fireSizeChange(DTBAdUtil.pixelsToDeviceIndependenPixels(this.endAnimation.width), DTBAdUtil.pixelsToDeviceIndependenPixels(this.endAnimation.height));
            setState(MraidStateType.EXPANDED);
            commandCompleted("expand");
            this.animater = null;
            getAdView().computeExposure(true);
            getAdView().setScrollEnabled(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$expand$7(Map map) {
        if (((String) map.get(DTBMetricsConfiguration.APSMETRICS_URL)) != null) {
            executeTwoPartsExpand(map);
        } else {
            executeOnePartExpand(map);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$impressionFired$19() {
        this.bannerListener.onImpressionFired(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$moveExpandedToDefaultImpl$3(ViewGroup viewGroup, boolean z, ValueAnimator valueAnimator) {
        if (updateAdViewLayout(valueAnimator).floatValue() == 1.0f) {
            updateExpandedToDefaultListener(viewGroup, z);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$moveResizedToDefaultImpl$1(ViewGroup viewGroup, boolean z, ValueAnimator valueAnimator) {
        if (updateAdViewLayout(valueAnimator).floatValue() == 1.0f) {
            updateResizedToDefaultListener(viewGroup, z);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdClicked$14(View view) {
        this.bannerListener.onAdClicked(view);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdFailedToLoad$17() {
        this.bannerListener.onAdFailed(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdLeftApplication$15() {
        this.bannerListener.onAdOpen(this.adView);
        this.bannerListener.onAdLeftApplication(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdLoaded$16() {
        this.bannerListener.onAdLoaded(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onMRAIDUnload$4() {
        getAdView().loadUrl("about:blank");
        commandCompleted("unload");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onResizeImpl$6(int i, int i2, int i3, int i4, ValueAnimator valueAnimator) {
        if (updateAdViewLayout(valueAnimator).floatValue() == 1.0f) {
            fireSizeChange(DTBAdUtil.pixelsToDeviceIndependenPixels(i), DTBAdUtil.pixelsToDeviceIndependenPixels(i2));
            addCloseIndicator(i3 + i, i4);
            commandCompleted("resize");
            setState(MraidStateType.RESIZED);
            this.animater = null;
            getAdView().computeExposure(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$passLoadError$18() {
        this.bannerListener.onAdError(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$updateExpandedToDefaultListener$11() {
        getAdView().loadUrl("about:blank");
        commandCompleted("unload");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$updateExpandedToDefaultListener$12() {
        getAdView().computeExposure(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$updateResizedToDefaultListener$10() {
        getAdView().computeExposure(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$updateResizedToDefaultListener$9() {
        getAdView().loadUrl("about:blank");
        commandCompleted("unload");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$useCustomButtonUpdated$13() {
        this.closeIndicatorRegion.setVisibility(this.useCustomClose ? 4 : 0);
    }

    private void moveExpandedToDefault() {
        moveExpandedToDefault(500, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: moveExpandedToDefaultImpl, reason: merged with bridge method [inline-methods] */
    public void lambda$moveExpandedToDefault$2(int i, boolean z) {
        ViewGroup viewGroup;
        AnimationPoint animationPoint = this.startAnimation;
        this.startAnimation = this.endAnimation;
        this.endAnimation = animationPoint;
        ViewGroup viewGroup2 = (ViewGroup) getAdView().getParent();
        LinearLayout linearLayout = this.closeIndicatorRegion;
        if (linearLayout != null && (viewGroup = (ViewGroup) linearLayout.getParent()) != null) {
            viewGroup.removeView(this.closeIndicatorRegion);
            this.closeIndicatorRegion = null;
        }
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "animationProgress", DefinitionKt.NO_Float_VALUE, 1.0f);
        this.animater = objectAnimatorOfFloat;
        objectAnimatorOfFloat.addUpdateListener(new d(this, viewGroup2, z, 0));
        this.animater.setDuration(i);
        this.animater.start();
    }

    private void moveResizedToDefault() {
        moveResizedToDefault(500, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: moveResizedToDefaultImpl, reason: merged with bridge method [inline-methods] */
    public void lambda$moveResizedToDefault$0(int i, boolean z) {
        AnimationPoint animationPoint = this.startAnimation;
        this.startAnimation = this.endAnimation;
        this.endAnimation = animationPoint;
        animationPoint.height = this.originalHeight;
        animationPoint.width = this.originalWidth;
        animationPoint.xPos = this.originalXPos;
        animationPoint.yPos = this.originalYPos;
        ViewGroup viewGroup = (ViewGroup) getAdView().getParent();
        LinearLayout linearLayout = this.closeIndicatorRegion;
        if (linearLayout != null) {
            viewGroup.removeView(linearLayout);
            this.closeIndicatorRegion = null;
        }
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "animationProgress", DefinitionKt.NO_Float_VALUE, 1.0f);
        this.animater = objectAnimatorOfFloat;
        objectAnimatorOfFloat.addUpdateListener(new d(this, viewGroup, z, 1));
        this.animater.setDuration(i);
        this.animater.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:21:0x00b4 A[PHI: r5 r11
  0x00b4: PHI (r5v2 int) = (r5v1 int), (r5v12 int) binds: [B:10:0x009f, B:19:0x00ae] A[DONT_GENERATE, DONT_INLINE]
  0x00b4: PHI (r11v2 int) = (r11v1 int), (r11v5 int) binds: [B:10:0x009f, B:19:0x00ae] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00fc A[PHI: r0 r2
  0x00fc: PHI (r0v4 int) = (r0v3 int), (r0v16 int) binds: [B:23:0x00e4, B:34:0x00f7] A[DONT_GENERATE, DONT_INLINE]
  0x00fc: PHI (r2v8 int) = (r2v7 int), (r2v14 int) binds: [B:23:0x00e4, B:34:0x00f7] A[DONT_GENERATE, DONT_INLINE]] */
    /* renamed from: onResizeImpl, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void lambda$onResize$5(int r15, int r16, int r17, int r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 376
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.device.ads.DTBAdMRAIDBannerController.lambda$onResize$5(int, int, int, int, boolean):void");
    }

    private Float updateAdViewLayout(ValueAnimator valueAnimator) {
        Float f = (Float) valueAnimator.getAnimatedValue();
        ViewGroup.LayoutParams layoutParams = getAdView().getLayoutParams();
        getAdView().setX((f.floatValue() * (this.endAnimation.xPos - r2)) + this.startAnimation.xPos);
        getAdView().setY((f.floatValue() * (this.endAnimation.yPos - r2)) + this.startAnimation.yPos);
        layoutParams.width = (int) ((f.floatValue() * (this.endAnimation.width - r1)) + this.startAnimation.width);
        layoutParams.height = (int) ((f.floatValue() * (this.endAnimation.height - r1)) + this.startAnimation.height);
        getAdView().setLayoutParams(layoutParams);
        getAdView().invalidate();
        return f;
    }

    private void updateExpandedToDefaultListener(ViewGroup viewGroup, boolean z) {
        getAdView().setIgnoreDetachment();
        viewGroup.removeView(getAdView());
        this.startAnimation = this.endAnimation;
        ViewGroup viewGroup2 = this.expandedBackground;
        if (viewGroup2 != null) {
            ((ViewGroup) viewGroup2.getParent()).removeView(this.expandedBackground);
            this.expandedBackground = null;
            fireSizeChange(DTBAdUtil.pixelsToDeviceIndependenPixels(this.startAnimation.width), DTBAdUtil.pixelsToDeviceIndependenPixels(this.startAnimation.height));
        }
        if (this.originalParams != null) {
            this.defaultParent.addView(getAdView(), this.originalParams);
            this.defaultParent.requestLayout();
        }
        setCurrentPositionProperty();
        setState(MraidStateType.DEFAULT);
        getAdView().setScrollEnabled(false);
        commandCompleted("close");
        this.defaultParent = null;
        this.animater = null;
        if (z) {
            new Handler().postDelayed(new b(this, 5), 500L);
        }
        new Handler().postDelayed(new b(this, 6), 100L);
    }

    private void updateResizedToDefaultListener(ViewGroup viewGroup, boolean z) {
        getAdView().setIgnoreDetachment();
        viewGroup.removeView(getAdView());
        this.startAnimation = this.endAnimation;
        if (this.originalParams != null) {
            this.defaultParent.addView(getAdView(), this.originalParams);
            this.defaultParent.requestLayout();
        }
        getAdView().invalidate();
        setCurrentPositionProperty();
        this.defaultParent = null;
        fireSizeChange(DTBAdUtil.pixelsToDeviceIndependenPixels(this.endAnimation.width), DTBAdUtil.pixelsToDeviceIndependenPixels(this.endAnimation.height));
        setState(MraidStateType.DEFAULT);
        this.animater = null;
        commandCompleted("close");
        if (z) {
            new Handler().postDelayed(new b(this, 7), 500L);
        }
        new Handler().postDelayed(new b(this, 8), 100L);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void closeExpandedPartTwo() {
        setState(MraidStateType.DEFAULT);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void expand(Map<String, Object> map) {
        if (this.state.equals(MraidStateType.DEFAULT)) {
            new Handler(Looper.getMainLooper()).post(new k(1, this, map));
        } else {
            fireErrorEvent("expand", "current state does not allow transition to expand");
            commandCompleted("expand");
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public String getPlacementType() {
        return "inline";
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void impressionFired() {
        DtbThreadService.executeOnMainThread(new b(this, 10));
        super.impressionFired();
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController, com.amazon.device.ads.DTBActivityListener
    public void onActivityDestroyed(Activity activity) {
        if (getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().stopOmAdSession();
        }
        ActivityMonitor.getInstance().setActivityListener(null);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController, com.amazon.device.ads.DTBActivityListener
    public void onActivityResumed(Activity activity) {
        this.bannerListener.onAdClosed(this.adView);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdClicked() {
        DTBAdView dTBAdView = this.adView;
        if (this.bannerListener != null) {
            new Handler(Looper.getMainLooper()).post(new k(2, this, dTBAdView));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdFailedToLoad() {
        if (this.bannerListener == null) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to get bannerListener on onAdFailedToLoad", null);
            return;
        }
        if (getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().stopOmAdSession();
        }
        DtbThreadService.executeOnMainThread(new b(this, 4));
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdLeftApplication() {
        new Handler(Looper.getMainLooper()).post(new b(this, 3));
        ActivityMonitor.getInstance().setActivityListener(this);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdLoaded() {
        if (this.bannerListener == null) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to get bannerListener on OnAdLoaded", null);
        } else {
            DtbThreadService.executeOnMainThread(new b(this, 1));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdRemoved() {
        ViewGroup viewGroup;
        if (this.adView == null) {
            return;
        }
        super.onAdRemoved();
        removeCloseIndicator();
        ObjectAnimator objectAnimator = this.animater;
        if (objectAnimator != null) {
            objectAnimator.end();
        }
        if (!isVisibleRecyclerOrListView(this.adView.getParent())) {
            this.adView.setVisibility(8);
        }
        MraidStateType mraidStateType = this.state;
        if (mraidStateType == MraidStateType.RESIZED) {
            ViewParent parent = this.adView.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(this.adView);
                return;
            }
            return;
        }
        if (mraidStateType == MraidStateType.EXPANDED && (viewGroup = this.expandedBackground) != null && (viewGroup.getParent() instanceof ViewGroup)) {
            ((ViewGroup) this.expandedBackground.getParent()).removeView(this.expandedBackground);
        }
    }

    public boolean onBackPressed() {
        return false;
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onMRAIDClose() {
        MraidStateType mraidStateType = this.state;
        if (mraidStateType == MraidStateType.RESIZED) {
            moveResizedToDefault();
            return;
        }
        if (mraidStateType == MraidStateType.EXPANDED) {
            moveExpandedToDefault();
            return;
        }
        if (mraidStateType == MraidStateType.DEFAULT) {
            setState(MraidStateType.HIDDEN);
            commandCompleted("close");
        } else {
            fireErrorEvent("close", "Command is not allowed in a given ad state:" + this.state.toString());
            commandCompleted("close");
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onMRAIDUnload() {
        MraidStateType mraidStateType = this.state;
        if (mraidStateType == MraidStateType.RESIZED) {
            moveResizedToDefault(10, true);
        } else if (mraidStateType == MraidStateType.EXPANDED) {
            moveExpandedToDefault(10, true);
        } else {
            new Handler(Looper.getMainLooper()).post(new b(this, 2));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onPageLoad() {
        try {
            if (!this.pageLoaded) {
                prepareMraid();
                if (DTBMetricsConfiguration.getInstance().isFeatureEnabled("additional_webview_metric", false)) {
                    com.amazon.aps.shared.a.c(null, "bannerCreativeFinished", getAdView().getBidId());
                }
            }
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute onPageLoad for Banner", e);
        }
        this.originalParams = getAdView().getLayoutParams();
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onResize(Map<String, Object> map) {
        final int iIntValue;
        final int iIntValue2;
        final int iIntValue3;
        final int iIntValue4;
        final boolean zBooleanValue;
        MraidStateType mraidStateType = this.state;
        if (mraidStateType != MraidStateType.DEFAULT && mraidStateType != MraidStateType.RESIZED) {
            fireErrorEvent("resize", "invalid current state");
            commandCompleted("resize");
            return;
        }
        try {
            iIntValue = map.containsKey("offsetX") ? ((Integer) map.get("offsetX")).intValue() : 0;
            iIntValue2 = map.containsKey("offsetY") ? ((Integer) map.get("offsetY")).intValue() : 0;
            iIntValue3 = ((Integer) map.get(OTUXParamsKeys.OT_UX_WIDTH)).intValue();
            iIntValue4 = ((Integer) map.get(OTUXParamsKeys.OT_UX_HEIGHT)).intValue();
            zBooleanValue = ((Boolean) map.get("allowOffscreen")).booleanValue();
        } catch (Exception unused) {
        }
        try {
            new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: com.amazon.device.ads.a
                @Override // java.lang.Runnable
                public final void run() {
                    this.a.lambda$onResize$5(iIntValue, iIntValue2, iIntValue3, iIntValue4, zBooleanValue);
                }
            });
        } catch (Exception unused2) {
            fireErrorEvent("resize", "invalid input parameters");
            commandCompleted("resize");
        }
    }

    public void openExpanded() {
        setState(MraidStateType.EXPANDED);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void passLoadError() {
        DtbThreadService.executeOnMainThread(new b(this, 0));
    }

    public void setAnimationProgress(float f) {
        this.animationProgress = f;
    }

    @Override // com.amazon.device.ads.DTBMRAIDCloseButtonListener
    public void useCustomButtonUpdated() {
        if (this.state != MraidStateType.EXPANDED || this.closeIndicatorRegion == null) {
            return;
        }
        new Handler(Looper.getMainLooper()).post(new b(this, 9));
    }

    private void moveExpandedToDefault(int i, boolean z) {
        new Handler(Looper.getMainLooper()).post(new e(this, i, z, 1));
    }

    private void moveResizedToDefault(int i, boolean z) {
        new Handler(Looper.getMainLooper()).post(new e(this, i, z, 0));
    }
}
