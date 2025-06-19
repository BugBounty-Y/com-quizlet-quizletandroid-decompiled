package androidx.work.impl.utils;

import android.net.NetworkRequest;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public static final String b;
    public final NetworkRequest a;

    static {
        String strE = z.e("NetworkRequestCompat");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"NetworkRequestCompat\")");
        b = strE;
    }

    public g(NetworkRequest networkRequest) {
        this.a = networkRequest;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        NetworkRequest networkRequest = this.a;
        if (networkRequest == null) {
            return 0;
        }
        return networkRequest.hashCode();
    }

    public final String toString() {
        return "NetworkRequestCompat(wrapped=" + this.a + ')';
    }
}
