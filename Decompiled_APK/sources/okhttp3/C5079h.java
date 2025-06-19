package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import java.util.ArrayList;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okhttp3.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5079h {
    public static final C5079h c = new C5079h(CollectionsKt.A0(new ArrayList()), null);
    public final Set a;
    public final AbstractC3375o2 b;

    public C5079h(Set pins, AbstractC3375o2 abstractC3375o2) {
        Intrinsics.checkNotNullParameter(pins, "pins");
        this.a = pins;
        this.b = abstractC3375o2;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0064  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.String r17, kotlin.jvm.functions.Function0 r18) throws java.security.NoSuchAlgorithmException, javax.net.ssl.SSLPeerUnverifiedException {
        /*
            Method dump skipped, instructions count: 423
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.C5079h.a(java.lang.String, kotlin.jvm.functions.Function0):void");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C5079h)) {
            return false;
        }
        C5079h c5079h = (C5079h) obj;
        return Intrinsics.b(c5079h.a, this.a) && Intrinsics.b(c5079h.b, this.b);
    }

    public final int hashCode() {
        int iHashCode = (this.a.hashCode() + 1517) * 41;
        AbstractC3375o2 abstractC3375o2 = this.b;
        return iHashCode + (abstractC3375o2 != null ? abstractC3375o2.hashCode() : 0);
    }
}
