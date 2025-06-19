package org.prebid.mobile;

import android.content.Context;
import org.prebid.mobile.SharedNetworkManager;
import org.prebid.mobile.VisibilityDetector;
import org.prebid.mobile.http.HTTPGet;
import org.prebid.mobile.http.HTTPResponse;

/* loaded from: classes3.dex */
class ImpressionTracker {
    public String a;
    public VisibilityDetector b;
    public boolean c;
    public Context d;
    public ImpressionListener e;
    public ImpressionTrackerListener f;

    /* renamed from: org.prebid.mobile.ImpressionTracker$2, reason: invalid class name */
    class AnonymousClass2 implements ImpressionTrackerListener {
        public AnonymousClass2() {
        }

        @Override // org.prebid.mobile.ImpressionTrackerListener
        public final void a() {
            ImpressionTrackerListener impressionTrackerListener = ImpressionTracker.this.f;
            if (impressionTrackerListener != null) {
                impressionTrackerListener.a();
            }
        }
    }

    public class ImpressionListener implements VisibilityDetector.VisibilityListener {
        public long a = 0;

        public ImpressionListener() {
        }

        public final void a(boolean z) {
            if (z) {
                this.a += 250;
            } else {
                this.a = 0L;
            }
            if (this.a >= 1000) {
                final ImpressionTracker impressionTracker = ImpressionTracker.this;
                synchronized (impressionTracker) {
                    try {
                        if (!impressionTracker.c) {
                            SharedNetworkManager sharedNetworkManagerA = SharedNetworkManager.a(impressionTracker.d);
                            if (sharedNetworkManagerA.b(impressionTracker.d)) {
                                new HTTPGet() { // from class: org.prebid.mobile.ImpressionTracker.1
                                    @Override // org.prebid.mobile.http.HTTPGet
                                    public final String c() {
                                        return ImpressionTracker.this.a;
                                    }

                                    @Override // org.prebid.mobile.http.HTTPGet
                                    public final void e(HTTPResponse hTTPResponse) {
                                        ImpressionTrackerListener impressionTrackerListener = ImpressionTracker.this.f;
                                        if (impressionTrackerListener != null) {
                                            impressionTrackerListener.a();
                                        }
                                    }
                                }.b();
                                impressionTracker.b.c.remove(impressionTracker.e);
                                impressionTracker.e = null;
                            } else {
                                String str = impressionTracker.a;
                                Context context = impressionTracker.d;
                                AnonymousClass2 anonymousClass2 = impressionTracker.new AnonymousClass2();
                                synchronized (sharedNetworkManagerA) {
                                    LogUtil.e(3, "PrebidMobile", "SharedNetworkManager adding URL for Network Retry");
                                    sharedNetworkManagerA.d = anonymousClass2;
                                    sharedNetworkManagerA.a.add(new SharedNetworkManager.UrlObject(str));
                                    sharedNetworkManagerA.c(context);
                                }
                            }
                            impressionTracker.c = true;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }
    }
}
