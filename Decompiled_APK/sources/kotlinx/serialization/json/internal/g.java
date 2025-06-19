package kotlinx.serialization.json.internal;

import androidx.appcompat.app.K;
import kotlin.A;
import kotlin.C;
import kotlin.D;
import kotlin.G;
import kotlin.H;
import kotlin.jvm.internal.Intrinsics;
import kotlin.z;

/* loaded from: classes3.dex */
public final class g extends K {
    public final boolean d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(com.android.billingclient.api.s writer, boolean z) {
        super(writer);
        Intrinsics.checkNotNullParameter(writer, "writer");
        this.d = z;
    }

    @Override // androidx.appcompat.app.K
    public final void A(int i) {
        if (this.d) {
            z zVar = A.b;
            E(Integer.toUnsignedString(i));
        } else {
            z zVar2 = A.b;
            C(Integer.toUnsignedString(i));
        }
    }

    @Override // androidx.appcompat.app.K
    public final void B(long j) {
        if (this.d) {
            C c = D.b;
            E(Long.toUnsignedString(j));
        } else {
            C c2 = D.b;
            C(Long.toUnsignedString(j));
        }
    }

    @Override // androidx.appcompat.app.K
    public final void D(short s) {
        if (this.d) {
            G g = H.b;
            E(String.valueOf(s & 65535));
        } else {
            G g2 = H.b;
            C(String.valueOf(s & 65535));
        }
    }

    @Override // androidx.appcompat.app.K
    public final void w(byte b) {
        if (this.d) {
            kotlin.w wVar = kotlin.x.b;
            E(String.valueOf(b & 255));
        } else {
            kotlin.w wVar2 = kotlin.x.b;
            C(String.valueOf(b & 255));
        }
    }
}
