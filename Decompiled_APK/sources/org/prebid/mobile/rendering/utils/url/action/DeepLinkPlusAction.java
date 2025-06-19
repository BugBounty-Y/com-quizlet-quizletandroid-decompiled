package org.prebid.mobile.rendering.utils.url.action;

import android.content.Context;
import android.net.Uri;
import java.util.Iterator;
import java.util.List;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.networking.tracking.ServerConnection;
import org.prebid.mobile.rendering.networking.tracking.TrackingManager;
import org.prebid.mobile.rendering.utils.helpers.ExternalViewerUtils;
import org.prebid.mobile.rendering.utils.url.ActionNotResolvedException;
import org.prebid.mobile.rendering.utils.url.UrlHandler;

/* loaded from: classes3.dex */
public class DeepLinkPlusAction implements UrlAction {
    @Override // org.prebid.mobile.rendering.utils.url.action.UrlAction
    public final void a(Context context, UrlHandler urlHandler, Uri uri) throws ActionNotResolvedException {
        if (!"navigate".equalsIgnoreCase(uri.getHost())) {
            throw new ActionNotResolvedException("Deeplink+ URL did not have 'navigate' as the host.");
        }
        try {
            String queryParameter = uri.getQueryParameter("primaryUrl");
            List<String> queryParameters = uri.getQueryParameters("primaryTrackingUrl");
            String queryParameter2 = uri.getQueryParameter("fallbackUrl");
            List<String> queryParameters2 = uri.getQueryParameters("fallbackTrackingUrl");
            if (queryParameter == null) {
                throw new ActionNotResolvedException("Deeplink+ did not have 'primaryUrl' query param.");
            }
            Uri uri2 = Uri.parse(queryParameter);
            if (b(uri2)) {
                throw new ActionNotResolvedException("Deeplink+ had another Deeplink+ as the 'primaryUrl'.");
            }
            try {
                ExternalViewerUtils.b(context, uri2);
                TrackingManager.a().getClass();
                if (queryParameters == null) {
                    LogUtil.e(3, "TrackingManager", "fireEventTrackingURLs(): Unable to execute event tracking requests. Provided list is null");
                    return;
                }
                Iterator<String> it2 = queryParameters.iterator();
                while (it2.hasNext()) {
                    ServerConnection.a(it2.next());
                }
            } catch (ActionNotResolvedException unused) {
                LogUtil.e(3, "DeepLinkPlusAction", "performAction(): Primary URL failed. Attempting to process fallback URL");
                if (queryParameter2 == null) {
                    throw new ActionNotResolvedException("Unable to handle 'primaryUrl' for Deeplink+ and 'fallbackUrl' was missing.");
                }
                if (b(Uri.parse(queryParameter2))) {
                    throw new ActionNotResolvedException("Deeplink+ URL had another Deeplink+ URL as the 'fallbackUrl'.");
                }
                urlHandler.b(context, queryParameter2, queryParameters2);
            }
        } catch (UnsupportedOperationException unused2) {
            throw new ActionNotResolvedException("Deeplink+ URL was not a hierarchical URI.");
        }
    }

    @Override // org.prebid.mobile.rendering.utils.url.action.UrlAction
    public final boolean b(Uri uri) {
        return "deeplink+".equalsIgnoreCase(uri.getScheme());
    }
}
