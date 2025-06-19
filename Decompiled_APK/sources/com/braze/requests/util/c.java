package com.braze.requests.util;

import android.net.Uri;
import java.net.URL;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final String a;
    public final Uri b;
    public final URL c;
    public final boolean d;

    public c(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.b = uri;
        String string = uri.toString();
        this.a = string;
        this.c = new URL(string);
        this.d = false;
    }

    public final String toString() {
        return this.a;
    }

    public c(String urlString, boolean z) {
        Intrinsics.checkNotNullParameter(urlString, "urlString");
        this.b = Uri.parse(urlString);
        this.a = urlString;
        this.c = new URL(urlString);
        this.d = z;
    }
}
