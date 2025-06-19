package androidx.privacysandbox.ads.adservices.topics;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final boolean a;

    public a(boolean z) {
        Intrinsics.checkNotNullParameter("com.google.android.gms.ads", "adsSdkName");
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        aVar.getClass();
        return this.a == aVar.a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a) + 1169068184;
    }

    public final String toString() {
        return "GetTopicsRequest: adsSdkName=com.google.android.gms.ads, shouldRecordObservation=" + this.a;
    }
}
