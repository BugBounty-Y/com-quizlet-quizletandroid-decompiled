package com.facebook.appevents.cloudbridge;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final String a;
    public final String b;
    public final String c;

    public g(String datasetID, String cloudBridgeURL, String accessKey) {
        Intrinsics.checkNotNullParameter(datasetID, "datasetID");
        Intrinsics.checkNotNullParameter(cloudBridgeURL, "cloudBridgeURL");
        Intrinsics.checkNotNullParameter(accessKey, "accessKey");
        this.a = datasetID;
        this.b = cloudBridgeURL;
        this.c = accessKey;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CloudBridgeCredentials(datasetID=");
        sb.append(this.a);
        sb.append(", cloudBridgeURL=");
        sb.append(this.b);
        sb.append(", accessKey=");
        return d0.r(sb, this.c, ')');
    }
}
