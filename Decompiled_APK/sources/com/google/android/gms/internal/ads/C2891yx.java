package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.yx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2891yx {
    public static final /* synthetic */ int f = 0;
    public final Uri a;
    public final Map b;
    public final long c;
    public final long d;
    public final int e;

    static {
        E3.a("media3.datasource");
    }

    public C2891yx(Uri uri, long j, long j2) {
        this(uri, Collections.EMPTY_MAP, j, j2, 0);
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("DataSpec[GET ", this.a.toString(), ", ");
        sbY.append(this.c);
        sbY.append(", ");
        sbY.append(this.d);
        sbY.append(", null, ");
        return android.support.v4.media.session.a.r(sbY, this.e, "]");
    }

    public C2891yx(Uri uri, Map map, long j, long j2, int i) {
        boolean z = false;
        boolean z2 = j >= 0;
        AbstractC1795We.B(z2);
        AbstractC1795We.B(z2);
        if (j2 > 0) {
            z = true;
        } else if (j2 == -1) {
            j2 = -1;
            z = true;
        }
        AbstractC1795We.B(z);
        uri.getClass();
        this.a = uri;
        this.b = Collections.unmodifiableMap(new HashMap(map));
        this.c = j;
        this.d = j2;
        this.e = i;
    }
}
