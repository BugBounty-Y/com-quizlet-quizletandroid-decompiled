package com.quizlet.quizletandroid.config;

import android.net.Uri;
import com.quizlet.login.magiclink.ui.e;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class c {
    public final u a;

    public c(d deepLinkLoader) {
        Intrinsics.checkNotNullParameter(deepLinkLoader, "deepLinkLoader");
        this.a = l.b(new e(deepLinkLoader, 4));
    }

    public final boolean a(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        List<Pattern> list = (List) this.a.getValue();
        if (list == null || !list.isEmpty()) {
            for (Pattern pattern : list) {
                String host = uri.getHost();
                if (host != null ? pattern.matcher(host).matches() : false) {
                    return true;
                }
            }
        }
        return false;
    }
}
