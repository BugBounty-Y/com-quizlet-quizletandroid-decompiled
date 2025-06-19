package com.google.android.gms.internal.measurement;

import android.net.Uri;
import androidx.collection.C0208f;

/* loaded from: classes2.dex */
public abstract class B1 {
    public static final C0208f a = new C0208f(0);

    public static synchronized Uri a() {
        C0208f c0208f = a;
        Uri uri = (Uri) c0208f.get("com.google.android.gms.measurement");
        if (uri != null) {
            return uri;
        }
        Uri uri2 = Uri.parse("content://com.google.android.gms.phenotype/".concat(String.valueOf(Uri.encode("com.google.android.gms.measurement"))));
        c0208f.put("com.google.android.gms.measurement", uri2);
        return uri2;
    }
}
