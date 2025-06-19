package kotlinx.serialization.json.internal;

import androidx.appcompat.app.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends K {
    public final kotlinx.serialization.json.c d;
    public int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(com.android.billingclient.api.s writer, kotlinx.serialization.json.c json) {
        super(writer);
        Intrinsics.checkNotNullParameter(writer, "writer");
        Intrinsics.checkNotNullParameter(json, "json");
        this.d = json;
    }

    @Override // androidx.appcompat.app.K
    public final void I() {
        x(' ');
    }

    @Override // androidx.appcompat.app.K
    public final void K() {
        this.e--;
    }

    @Override // androidx.appcompat.app.K
    public final void s() {
        this.a = true;
        this.e++;
    }

    @Override // androidx.appcompat.app.K
    public final void u() {
        this.a = false;
        C("\n");
        int i = this.e;
        for (int i2 = 0; i2 < i; i2++) {
            C(this.d.a.f);
        }
    }

    @Override // androidx.appcompat.app.K
    public final void v() {
        if (this.a) {
            this.a = false;
        } else {
            u();
        }
    }
}
