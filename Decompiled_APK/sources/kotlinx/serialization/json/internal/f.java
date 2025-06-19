package kotlinx.serialization.json.internal;

import androidx.appcompat.app.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends K {
    public final boolean d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.android.billingclient.api.s writer, boolean z) {
        super(writer);
        Intrinsics.checkNotNullParameter(writer, "writer");
        this.d = z;
    }

    @Override // androidx.appcompat.app.K
    public final void E(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        if (this.d) {
            super.E(value);
        } else {
            C(value);
        }
    }
}
