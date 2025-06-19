package com.google.firebase.sessions.settings;

import android.net.Uri;
import com.amazon.device.ads.DtbConstants;
import com.google.firebase.sessions.C3979a;
import com.google.firebase.sessions.C3980b;
import java.net.URL;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g {
    public final C3980b a;
    public final CoroutineContext b;

    public g(C3980b appInfo, CoroutineContext blockingDispatcher) {
        Intrinsics.checkNotNullParameter(appInfo, "appInfo");
        Intrinsics.checkNotNullParameter(blockingDispatcher, "blockingDispatcher");
        this.a = appInfo;
        this.b = blockingDispatcher;
    }

    public static final URL a(g gVar) {
        gVar.getClass();
        Uri.Builder builderAppendPath = new Uri.Builder().scheme("https").authority("firebase-settings.crashlytics.com").appendPath("spi").appendPath("v2").appendPath("platforms").appendPath(DtbConstants.NATIVE_OS_NAME).appendPath("gmp");
        C3980b c3980b = gVar.a;
        Uri.Builder builderAppendPath2 = builderAppendPath.appendPath(c3980b.a).appendPath("settings");
        C3979a c3979a = c3980b.b;
        return new URL(builderAppendPath2.appendQueryParameter("build_version", c3979a.c).appendQueryParameter("display_version", c3979a.b).build().toString());
    }
}
