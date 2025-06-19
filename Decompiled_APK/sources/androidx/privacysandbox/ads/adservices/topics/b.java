package androidx.privacysandbox.ads.adservices.topics;

import com.google.android.gms.internal.ads.AbstractC2330lu;
import java.util.HashSet;
import java.util.Objects;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final AbstractC2330lu a;
    public final K b;

    public b(AbstractC2330lu topics) {
        Intrinsics.checkNotNullParameter(topics, "topics");
        K encryptedTopics = K.a;
        Intrinsics.checkNotNullParameter(topics, "topics");
        Intrinsics.checkNotNullParameter(encryptedTopics, "encryptedTopics");
        this.a = topics;
        this.b = encryptedTopics;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        AbstractC2330lu abstractC2330lu = this.a;
        b bVar = (b) obj;
        if (abstractC2330lu.size() != bVar.a.size()) {
            return false;
        }
        K k = this.b;
        k.getClass();
        K k2 = bVar.b;
        k2.getClass();
        return new HashSet(abstractC2330lu).equals(new HashSet(bVar.a)) && new HashSet(k).equals(new HashSet(k2));
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b);
    }

    public final String toString() {
        return "GetTopicsResponse: Topics=" + this.a + ", EncryptedTopics=" + this.b;
    }
}
