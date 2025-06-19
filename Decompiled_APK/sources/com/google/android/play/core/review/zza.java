package com.google.android.play.core.review;

import android.app.PendingIntent;

/* loaded from: classes2.dex */
final class zza extends ReviewInfo {
    public final PendingIntent a;
    public final boolean b;

    public zza(PendingIntent pendingIntent, boolean z) {
        if (pendingIntent == null) {
            throw new NullPointerException("Null pendingIntent");
        }
        this.a = pendingIntent;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof ReviewInfo) {
            ReviewInfo reviewInfo = (ReviewInfo) obj;
            if (this.a.equals(((zza) reviewInfo).a) && this.b == ((zza) reviewInfo).b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ (true != this.b ? 1237 : 1231);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o("}", android.support.v4.media.session.a.y("ReviewInfo{pendingIntent=", this.a.toString(), ", isNoOp="), this.b);
    }
}
