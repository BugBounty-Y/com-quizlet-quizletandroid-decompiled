package com.quizlet.shared.quizletapi;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.amazon.device.ads.DtbConstants;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;

    public b(String baseUrl) {
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        this.a = baseUrl;
    }

    public static String a(b bVar, String path, String str, int i) {
        if ((i & 2) != 0) {
            str = null;
        }
        a apiVersion = a.a;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(apiVersion, "apiVersion");
        String str2 = bVar.a;
        return str != null ? android.support.v4.media.session.a.t(AbstractC0147y.h(DtbConstants.HTTPS, str2, "/", "3.11/", path), "/", str) : AbstractC0147y.e(DtbConstants.HTTPS, str2, "/", "3.11/", path);
    }
}
