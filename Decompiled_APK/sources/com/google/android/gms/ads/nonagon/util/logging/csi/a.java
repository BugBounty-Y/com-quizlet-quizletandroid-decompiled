package com.google.android.gms.ads.nonagon.util.logging.csi;

import android.net.Uri;
import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import java.io.File;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes2.dex */
public final class a implements h {
    public String a;

    public String a(Map map) {
        Uri.Builder builderBuildUpon = Uri.parse(this.a).buildUpon();
        for (Map.Entry entry : map.entrySet()) {
            builderBuildUpon.appendQueryParameter((String) entry.getKey(), (String) entry.getValue());
        }
        return builderBuildUpon.build().toString();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        File file = (File) obj;
        Intrinsics.checkNotNullParameter(file, "file");
        if (file.exists() && file.length() > 0) {
            return g.c(file);
        }
        boolean zExists = file.exists();
        f fVar = f.a;
        if (zExists) {
            c.a.g(android.support.v4.media.session.a.t(android.support.v4.media.session.a.y("Deleting ", file.getPath(), " from "), this.a, " because it's size 0"), new Object[0]);
            file.delete();
        }
        return fVar;
    }
}
