package org.prebid.mobile.rendering.utils.url.action;

import android.content.Context;
import android.net.Uri;
import org.prebid.mobile.rendering.utils.url.UrlHandler;

/* loaded from: classes3.dex */
public interface UrlAction {
    void a(Context context, UrlHandler urlHandler, Uri uri);

    boolean b(Uri uri);
}
