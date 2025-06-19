package org.prebid.mobile.rendering.utils.url;

import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.text.TextUtils;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.mraid.methods.network.UrlResolutionTask;
import org.prebid.mobile.rendering.networking.tracking.ServerConnection;
import org.prebid.mobile.rendering.networking.tracking.TrackingManager;
import org.prebid.mobile.rendering.utils.url.action.UrlAction;

/* loaded from: classes3.dex */
public class UrlHandler {
    public static final UrlHandlerResultListener e = new UrlHandlerResultListener() { // from class: org.prebid.mobile.rendering.utils.url.UrlHandler.1
        @Override // org.prebid.mobile.rendering.utils.url.UrlHandler.UrlHandlerResultListener
        public final void a(String str) {
        }

        @Override // org.prebid.mobile.rendering.utils.url.UrlHandler.UrlHandlerResultListener
        public final void onSuccess() {
        }
    };
    public final HashSet a;
    public final UrlHandlerResultListener b;
    public boolean d = false;
    public boolean c = false;

    public static class Builder {
        public final HashSet a = new HashSet();
        public UrlHandlerResultListener b = UrlHandler.e;
    }

    public interface UrlHandlerResultListener {
        void a(String str);

        void onSuccess();
    }

    public UrlHandler(HashSet hashSet, UrlHandlerResultListener urlHandlerResultListener) {
        this.a = hashSet;
        this.b = urlHandlerResultListener;
    }

    public final boolean a(Context context, String str, List list) {
        boolean zIsEmpty = TextUtils.isEmpty(str);
        UrlHandlerResultListener urlHandlerResultListener = this.b;
        if (zIsEmpty) {
            urlHandlerResultListener.a(str);
            LogUtil.b("UrlHandler", "handleResolvedUrl(): Attempted to handle empty url.");
            return false;
        }
        Uri uri = Uri.parse(str);
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            UrlAction urlAction = (UrlAction) it2.next();
            if (urlAction.b(uri)) {
                try {
                    urlAction.a(context, this, uri);
                    if (this.c || this.d) {
                        LogUtil.e(5, "UrlHandler", "notifySuccess(): Action is finished or action is still pending.");
                    } else {
                        TrackingManager.a().getClass();
                        if (list == null) {
                            LogUtil.e(3, "TrackingManager", "fireEventTrackingURLs(): Unable to execute event tracking requests. Provided list is null");
                        } else {
                            Iterator it3 = list.iterator();
                            while (it3.hasNext()) {
                                ServerConnection.a((String) it3.next());
                            }
                        }
                        urlHandlerResultListener.onSuccess();
                        this.c = true;
                    }
                    return true;
                } catch (ActionNotResolvedException unused) {
                    LogUtil.b("UrlHandler", "handleResolvedUrl(): Unable to handle action: " + urlAction + " for given uri: " + uri);
                }
            }
        }
        urlHandlerResultListener.a(str);
        return false;
    }

    public final void b(final Context context, final String str, final List list) {
        if (TextUtils.isEmpty(str.trim())) {
            this.b.a(str);
            LogUtil.b("UrlHandler", "handleUrl(): Attempted to handle empty url.");
        } else {
            new UrlResolutionTask(new UrlResolutionTask.UrlResolutionListener() { // from class: org.prebid.mobile.rendering.utils.url.UrlHandler.2
                @Override // org.prebid.mobile.rendering.mraid.methods.network.UrlResolutionTask.UrlResolutionListener
                public final void a() {
                    UrlHandler urlHandler = UrlHandler.this;
                    urlHandler.d = false;
                    urlHandler.b.a(str);
                    UrlHandlerResultListener urlHandlerResultListener = UrlHandler.e;
                    LogUtil.b("UrlHandler", "Task for resolving url was cancelled");
                }

                @Override // org.prebid.mobile.rendering.mraid.methods.network.UrlResolutionTask.UrlResolutionListener
                public final void b(String str2) {
                    UrlHandler urlHandler = UrlHandler.this;
                    urlHandler.d = false;
                    urlHandler.a(context, str2, list);
                }
            }).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, str);
            this.d = true;
        }
    }
}
