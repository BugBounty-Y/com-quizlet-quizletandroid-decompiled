package org.prebid.mobile;

import android.os.CountDownTimer;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import com.perimeterx.mobile_sdk.web_view_interception.h;
import java.lang.ref.WeakReference;
import org.prebid.mobile.rendering.models.CreativeVisibilityTracker;

/* loaded from: classes3.dex */
public class VisibilityMonitor {
    public final boolean a = false;
    public final VisibilityTimer b = new VisibilityTimer();

    public static class VisibilityTimer extends CountDownTimer {
        public static final /* synthetic */ int g = 0;
        public int a;
        public boolean b;
        public String c;
        public String d;
        public WeakReference e;
        public CreativeVisibilityTracker f;

        public VisibilityTimer() {
            super(2147483647L, 500L);
        }

        public static WebView b(ViewGroup viewGroup) {
            WebView webViewB;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                View childAt = viewGroup.getChildAt(i);
                if (childAt instanceof WebView) {
                    return (WebView) childAt;
                }
                if ((childAt instanceof ViewGroup) && (webViewB = b((ViewGroup) childAt)) != null) {
                    return webViewB;
                }
            }
            return null;
        }

        public final void a() {
            if (this.f != null) {
                LogUtil.e(3, "VisibilityTimer", "Destroying");
                this.f.a();
                this.f = null;
            }
            cancel();
        }

        @Override // android.os.CountDownTimer
        public final void onFinish() {
        }

        @Override // android.os.CountDownTimer
        public final void onTick(long j) {
            View view = (View) this.e.get();
            if (view == null) {
                LogUtil.e(3, "VisibilityTimer", "Cancelled due to ad view is null");
                a();
                return;
            }
            WebView webViewB = view instanceof WebView ? (WebView) view : view instanceof ViewGroup ? b((ViewGroup) view) : null;
            if (webViewB == null || this.a == webViewB.hashCode()) {
                return;
            }
            this.a = webViewB.hashCode();
            if (this.b) {
                LogUtil.e(3, "VisibilityTimer", "Interstitial WebView found. Stopping...");
                a();
            }
            webViewB.evaluateJavascript("document.body.innerHTML", new h(new c(this.d, new WeakReference(webViewB), this, this.a), 1));
        }
    }
}
