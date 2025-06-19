package org.prebid.mobile;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewTreeObserver;
import android.webkit.WebView;
import androidx.core.view.V;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;
import org.prebid.mobile.VisibilityMonitor;
import org.prebid.mobile.rendering.models.CreativeVisibilityTracker;
import org.prebid.mobile.rendering.models.internal.VisibilityTrackerOption;
import org.prebid.mobile.rendering.models.ntv.NativeEventTracker$EventType;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;

/* loaded from: classes3.dex */
public final /* synthetic */ class c {
    public final /* synthetic */ String a;
    public final /* synthetic */ WeakReference b;
    public final /* synthetic */ VisibilityMonitor.VisibilityTimer c;
    public final /* synthetic */ int d;

    public /* synthetic */ c(String str, WeakReference weakReference, VisibilityMonitor.VisibilityTimer visibilityTimer, int i) {
        this.a = str;
        this.b = weakReference;
        this.c = visibilityTimer;
        this.d = i;
    }

    public final void a(String str) {
        int i = VisibilityMonitor.VisibilityTimer.g;
        if (str == null || str.isEmpty()) {
            return;
        }
        if (!str.equals(this.a)) {
            LogUtil.e(5, "VisibilityTimer", "Different cache ids");
            return;
        }
        WebView webView = (WebView) this.b.get();
        if (webView == null) {
            return;
        }
        VisibilityMonitor.VisibilityTimer visibilityTimer = this.c;
        CreativeVisibilityTracker creativeVisibilityTracker = visibilityTimer.f;
        if (creativeVisibilityTracker != null) {
            creativeVisibilityTracker.a();
        }
        NativeEventTracker$EventType nativeEventTracker$EventType = NativeEventTracker$EventType.a;
        VisibilityTrackerOption visibilityTrackerOption = new VisibilityTrackerOption();
        visibilityTrackerOption.e = Long.MIN_VALUE;
        visibilityTrackerOption.a = nativeEventTracker$EventType;
        visibilityTrackerOption.b = 0;
        visibilityTrackerOption.c = 1;
        CreativeVisibilityTracker creativeVisibilityTracker2 = new CreativeVisibilityTracker(webView, visibilityTrackerOption);
        visibilityTimer.f = creativeVisibilityTracker2;
        creativeVisibilityTracker2.g = new d(visibilityTimer);
        Context contextA = PrebidContextHolder.a();
        WeakReference weakReference = creativeVisibilityTracker2.c;
        if (weakReference == null || weakReference.get() == null) {
            LogUtil.b("CreativeVisibilityTracker", "Couldn't start visibility check. Target view is null");
        } else {
            View view = (View) weakReference.get();
            ViewTreeObserver viewTreeObserver = (ViewTreeObserver) creativeVisibilityTracker2.b.get();
            if (viewTreeObserver == null || !viewTreeObserver.isAlive()) {
                View viewFindViewById = null;
                View viewFindViewById2 = !(contextA instanceof Activity) ? null : ((Activity) contextA).getWindow().getDecorView().findViewById(R.id.content);
                if (view != null) {
                    WeakHashMap weakHashMap = V.a;
                    if (!view.isAttachedToWindow()) {
                        LogUtil.e(3, "Views", "Attempting to call View.getRootView() on an unattached View.");
                    }
                    View rootView = view.getRootView();
                    if (rootView != null && (viewFindViewById = rootView.findViewById(R.id.content)) == null) {
                        viewFindViewById = rootView;
                    }
                }
                if (viewFindViewById2 == null) {
                    viewFindViewById2 = viewFindViewById;
                }
                if (viewFindViewById2 == null) {
                    LogUtil.e(3, "CreativeVisibilityTracker", "Unable to set Visibility Tracker due to no available root view.");
                } else {
                    ViewTreeObserver viewTreeObserver2 = viewFindViewById2.getViewTreeObserver();
                    if (viewTreeObserver2.isAlive()) {
                        creativeVisibilityTracker2.b = new WeakReference(viewTreeObserver2);
                        viewTreeObserver2.addOnPreDrawListener(creativeVisibilityTracker2.a);
                    } else {
                        LogUtil.e(3, "CreativeVisibilityTracker", "Visibility Tracker was unable to track views because the root view tree observer was not alive");
                    }
                }
            } else {
                LogUtil.e(3, "CreativeVisibilityTracker", "Original ViewTreeObserver is still alive.");
            }
        }
        LogUtil.e(3, "VisibilityTimer", "Registering the new WebView: " + this.d);
    }
}
