package org.prebid.mobile;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import org.prebid.mobile.ImpressionTracker;
import org.prebid.mobile.http.HTTPGet;
import org.prebid.mobile.http.HTTPResponse;
import org.prebid.mobile.http.HttpErrorCode;

/* loaded from: classes3.dex */
public class SharedNetworkManager {
    public static SharedNetworkManager f;
    public ArrayList a;
    public Timer b;
    public boolean c;
    public ImpressionTrackerListener d;
    public ClickTrackerListener e;

    public class UrlObject {
        public final String a;
        public int b = 0;

        public UrlObject(String str) {
            this.a = str;
        }
    }

    public static SharedNetworkManager a(Context context) {
        if (f == null) {
            SharedNetworkManager sharedNetworkManager = new SharedNetworkManager();
            sharedNetworkManager.a = new ArrayList();
            sharedNetworkManager.c = context.getPackageManager().checkPermission("android.permission.ACCESS_NETWORK_STATE", context.getPackageName()) == 0;
            f = sharedNetworkManager;
        }
        return f;
    }

    public final boolean b(Context context) {
        if (!this.c) {
            return true;
        }
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public final void c(Context context) {
        if (this.b == null) {
            final WeakReference weakReference = new WeakReference(context);
            Timer timer = new Timer();
            this.b = timer;
            timer.scheduleAtFixedRate(new TimerTask() { // from class: org.prebid.mobile.SharedNetworkManager.1
                @Override // java.util.TimerTask, java.lang.Runnable
                public final void run() {
                    Timer timer2;
                    Context context2 = (Context) weakReference.get();
                    SharedNetworkManager sharedNetworkManager = SharedNetworkManager.this;
                    if (context2 == null) {
                        Timer timer3 = sharedNetworkManager.b;
                        if (timer3 != null) {
                            timer3.cancel();
                            sharedNetworkManager.b = null;
                            return;
                        }
                        return;
                    }
                    while (!sharedNetworkManager.a.isEmpty() && sharedNetworkManager.b(context2)) {
                        final UrlObject urlObject = (UrlObject) sharedNetworkManager.a.remove(0);
                        if (urlObject.b < 3) {
                            new HTTPGet() { // from class: org.prebid.mobile.SharedNetworkManager.1.1
                                @Override // org.prebid.mobile.http.HTTPGet
                                public final String c() {
                                    return urlObject.a;
                                }

                                @Override // org.prebid.mobile.http.HTTPGet
                                public final void e(HTTPResponse hTTPResponse) {
                                    AnonymousClass1 anonymousClass1 = AnonymousClass1.this;
                                    boolean z = hTTPResponse.a;
                                    SharedNetworkManager sharedNetworkManager2 = SharedNetworkManager.this;
                                    if (!z && hTTPResponse.b == HttpErrorCode.a) {
                                        UrlObject urlObject2 = urlObject;
                                        urlObject2.b++;
                                        sharedNetworkManager2.a.add(urlObject2);
                                    } else {
                                        ImpressionTrackerListener impressionTrackerListener = sharedNetworkManager2.d;
                                        if (impressionTrackerListener != null) {
                                            ((ImpressionTracker.AnonymousClass2) impressionTrackerListener).a();
                                        }
                                        ClickTrackerListener clickTrackerListener = sharedNetworkManager2.e;
                                    }
                                }
                            }.b();
                        }
                    }
                    if (!sharedNetworkManager.a.isEmpty() || (timer2 = sharedNetworkManager.b) == null) {
                        return;
                    }
                    timer2.cancel();
                    sharedNetworkManager.b = null;
                }
            }, 10000L, 10000L);
        }
    }
}
