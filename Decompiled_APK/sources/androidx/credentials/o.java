package androidx.credentials;

import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o {
    public final List a;

    public o(List credentialOptions) {
        Intrinsics.checkNotNullParameter(credentialOptions, "credentialOptions");
        this.a = credentialOptions;
        if (credentialOptions.isEmpty()) {
            throw new IllegalArgumentException("credentialOptions should not be empty");
        }
        if (credentialOptions.size() > 1) {
            if (!credentialOptions.isEmpty()) {
                Iterator it2 = credentialOptions.iterator();
                while (it2.hasNext()) {
                }
            }
            for (q qVar : this.a) {
            }
        }
    }
}
