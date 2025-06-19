package androidx.privacysandbox.ads.adservices.topics;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class i {
    public i() {
        Intrinsics.checkNotNullParameter(null, "mTopicsManager");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object d(androidx.privacysandbox.ads.adservices.topics.i r4, androidx.privacysandbox.ads.adservices.topics.a r5, kotlin.coroutines.h<? super androidx.privacysandbox.ads.adservices.topics.b> r6) {
        /*
            boolean r0 = r6 instanceof androidx.privacysandbox.ads.adservices.topics.h
            if (r0 == 0) goto L13
            r0 = r6
            androidx.privacysandbox.ads.adservices.topics.h r0 = (androidx.privacysandbox.ads.adservices.topics.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.privacysandbox.ads.adservices.topics.h r0 = new androidx.privacysandbox.ads.adservices.topics.h
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r0 = r0.l
            r1 = 0
            if (r0 == 0) goto L38
            r4 = 1
            if (r0 != r4) goto L30
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6.getClass()
            java.lang.ClassCastException r4 = new java.lang.ClassCastException
            r4.<init>()
            throw r4
        L30:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r4.a(r5)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.privacysandbox.ads.adservices.topics.i.d(androidx.privacysandbox.ads.adservices.topics.i, androidx.privacysandbox.ads.adservices.topics.a, kotlin.coroutines.h):java.lang.Object");
    }

    public void a(a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(request, "request");
        throw new RuntimeException("Stub!");
    }

    public b b() {
        Intrinsics.checkNotNullParameter(null, "response");
        Intrinsics.checkNotNullParameter(null, "response");
        new ArrayList();
        throw null;
    }

    public Object c(@NotNull a aVar, @NotNull kotlin.coroutines.h<? super b> hVar) {
        return d(this, aVar, hVar);
    }
}
