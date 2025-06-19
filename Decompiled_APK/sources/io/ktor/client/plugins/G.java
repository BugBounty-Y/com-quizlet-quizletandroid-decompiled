package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class G {
    public static final Set a;
    public static final org.slf4j.b b;
    public static final com.quizlet.quizletandroid.ui.login.di.a c;
    public static final io.ktor.client.plugins.api.d d;

    static {
        io.ktor.http.p[] elements = {io.ktor.http.p.b, io.ktor.http.p.d};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
        b = AbstractC3189k7.d("io.ktor.client.plugins.HttpRedirect");
        c = new com.quizlet.quizletandroid.ui.login.di.a(5);
        d = V6.a("HttpRedirect", E.a, new com.sdk.growthbook.utils.a(11));
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0183  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0211 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x022c  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x022f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:60:0x0212 -> B:61:0x0218). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(io.ktor.client.plugins.api.g r17, io.ktor.client.request.c r18, io.ktor.client.call.b r19, io.ktor.client.c r20, kotlin.coroutines.jvm.internal.c r21) {
        /*
            Method dump skipped, instructions count: 567
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.G.a(io.ktor.client.plugins.api.g, io.ktor.client.request.c, io.ktor.client.call.b, io.ktor.client.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final boolean b(io.ktor.http.r rVar) {
        int i = rVar.a;
        io.ktor.http.r rVar2 = io.ktor.http.r.c;
        return i == io.ktor.http.r.c.a || i == io.ktor.http.r.d.a || i == io.ktor.http.r.f.a || i == io.ktor.http.r.g.a || i == io.ktor.http.r.e.a;
    }
}
