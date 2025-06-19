package org.prebid.mobile.rendering.utils.url.action;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import org.prebid.mobile.rendering.utils.helpers.ExternalViewerUtils;
import org.prebid.mobile.rendering.utils.url.ActionNotResolvedException;
import org.prebid.mobile.rendering.utils.url.UrlHandler;

/* loaded from: classes3.dex */
public class DeepLinkAction implements UrlAction {
    @Override // org.prebid.mobile.rendering.utils.url.action.UrlAction
    public final void a(Context context, UrlHandler urlHandler, Uri uri) throws ActionNotResolvedException {
        ExternalViewerUtils.b(context, uri);
    }

    @Override // org.prebid.mobile.rendering.utils.url.action.UrlAction
    public final boolean b(Uri uri) {
        String scheme = uri.getScheme();
        return (TextUtils.isEmpty(scheme) || "http".equals(scheme) || "https".equals(scheme) || "deeplink+".equals(scheme)) ? false : true;
    }
}
