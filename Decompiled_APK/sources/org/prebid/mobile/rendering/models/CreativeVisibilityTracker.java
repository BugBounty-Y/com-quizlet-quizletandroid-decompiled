package org.prebid.mobile.rendering.models;

import android.os.Handler;
import android.os.Looper;
import android.view.ViewTreeObserver;
import android.webkit.WebView;
import com.google.firebase.crashlytics.internal.metadata.q;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import org.prebid.mobile.d;
import org.prebid.mobile.rendering.models.internal.VisibilityTrackerOption;
import org.prebid.mobile.rendering.utils.exposure.ViewExposureChecker;
import org.prebid.mobile.rendering.utils.helpers.VisibilityChecker;

/* loaded from: classes3.dex */
public class CreativeVisibilityTracker {
    public final a a;
    public WeakReference b;
    public final WeakReference c;
    public final ArrayList d;
    public final q e;
    public final Handler f;
    public d g;
    public boolean h;

    /* JADX WARN: Type inference failed for: r4v4, types: [org.prebid.mobile.rendering.models.a] */
    public CreativeVisibilityTracker(WebView webView, VisibilityTrackerOption visibilityTrackerOption) {
        Set setSingleton = Collections.singleton(visibilityTrackerOption);
        this.d = new ArrayList();
        this.c = new WeakReference(webView);
        ViewExposureChecker viewExposureChecker = new ViewExposureChecker();
        Iterator it2 = setSingleton.iterator();
        while (it2.hasNext()) {
            this.d.add(new VisibilityChecker((VisibilityTrackerOption) it2.next(), viewExposureChecker));
        }
        this.f = new Handler(Looper.getMainLooper());
        this.e = new q(this, 25);
        this.a = new ViewTreeObserver.OnPreDrawListener() { // from class: org.prebid.mobile.rendering.models.a
            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public final boolean onPreDraw() {
                CreativeVisibilityTracker creativeVisibilityTracker = this.a;
                if (!creativeVisibilityTracker.h) {
                    creativeVisibilityTracker.h = true;
                    creativeVisibilityTracker.f.postDelayed(creativeVisibilityTracker.e, 200L);
                }
                return true;
            }
        };
        this.b = new WeakReference(null);
    }

    public final void a() {
        this.f.removeCallbacksAndMessages(null);
        this.h = false;
        ViewTreeObserver viewTreeObserver = (ViewTreeObserver) this.b.get();
        if (viewTreeObserver != null && viewTreeObserver.isAlive()) {
            viewTreeObserver.removeOnPreDrawListener(this.a);
        }
        this.b.clear();
    }
}
