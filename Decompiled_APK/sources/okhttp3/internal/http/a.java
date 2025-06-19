package okhttp3.internal.http;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import okhttp3.A;
import okhttp3.H;
import okhttp3.n;
import okhttp3.u;

/* loaded from: classes3.dex */
public final class a implements u {
    public final /* synthetic */ int a = 1;
    public final Object b;

    public a(n cookieJar) {
        Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
        this.b = cookieJar;
    }

    public static int c(H h, int i) throws NumberFormatException {
        String strA = H.a("Retry-After", h);
        if (strA == null) {
            return i;
        }
        if (!new Regex("\\d+").e(strA)) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        Integer numValueOf = Integer.valueOf(strA);
        Intrinsics.checkNotNullExpressionValue(numValueOf, "valueOf(header)");
        return numValueOf.intValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:76:0x00e0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public okhttp3.C a(okhttp3.H r12, androidx.compose.material.ripple.r r13) throws java.net.ProtocolException {
        /*
            Method dump skipped, instructions count: 380
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http.a.a(okhttp3.H, androidx.compose.material.ripple.r):okhttp3.C");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0093  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean b(java.io.IOException r4, okhttp3.internal.connection.g r5, okhttp3.C r6, boolean r7) {
        /*
            r3 = this;
            java.lang.Object r0 = r3.b
            okhttp3.A r0 = (okhttp3.A) r0
            boolean r0 = r0.f
            r1 = 0
            if (r0 != 0) goto Lb
            goto Laf
        Lb:
            if (r7 == 0) goto L1a
            okhttp3.F r6 = r6.d
            if (r6 == 0) goto L15
            boolean r6 = r6 instanceof io.ktor.client.engine.okhttp.i
            if (r6 != 0) goto Laf
        L15:
            boolean r6 = r4 instanceof java.io.FileNotFoundException
            if (r6 == 0) goto L1a
            return r1
        L1a:
            boolean r6 = r4 instanceof java.net.ProtocolException
            if (r6 == 0) goto L1f
            return r1
        L1f:
            boolean r6 = r4 instanceof java.io.InterruptedIOException
            if (r6 == 0) goto L2a
            boolean r4 = r4 instanceof java.net.SocketTimeoutException
            if (r4 == 0) goto Laf
            if (r7 != 0) goto Laf
            goto L3d
        L2a:
            boolean r6 = r4 instanceof javax.net.ssl.SSLHandshakeException
            if (r6 == 0) goto L38
            java.lang.Throwable r6 = r4.getCause()
            boolean r6 = r6 instanceof java.security.cert.CertificateException
            if (r6 == 0) goto L38
            goto Laf
        L38:
            boolean r4 = r4 instanceof javax.net.ssl.SSLPeerUnverifiedException
            if (r4 == 0) goto L3d
            return r1
        L3d:
            androidx.constraintlayout.core.motion.utils.l r4 = r5.h
            kotlin.jvm.internal.Intrinsics.d(r4)
            int r5 = r4.b
            r6 = 1
            if (r5 != 0) goto L51
            int r7 = r4.c
            if (r7 != 0) goto L51
            int r7 = r4.d
            if (r7 != 0) goto L51
            r4 = r1
            goto Lad
        L51:
            java.lang.Object r7 = r4.j
            okhttp3.K r7 = (okhttp3.K) r7
            if (r7 == 0) goto L58
            goto La8
        L58:
            r7 = 0
            if (r5 > r6) goto L8f
            int r5 = r4.c
            if (r5 > r6) goto L8f
            int r5 = r4.d
            if (r5 <= 0) goto L64
            goto L8f
        L64:
            java.lang.Cloneable r5 = r4.g
            okhttp3.internal.connection.g r5 = (okhttp3.internal.connection.g) r5
            okhttp3.internal.connection.i r5 = r5.i
            if (r5 != 0) goto L6d
            goto L8f
        L6d:
            monitor-enter(r5)
            int r0 = r5.l     // Catch: java.lang.Throwable -> L8c
            if (r0 == 0) goto L74
            monitor-exit(r5)
            goto L8f
        L74:
            okhttp3.K r0 = r5.b     // Catch: java.lang.Throwable -> L8c
            okhttp3.a r0 = r0.a     // Catch: java.lang.Throwable -> L8c
            okhttp3.s r0 = r0.h     // Catch: java.lang.Throwable -> L8c
            java.lang.Object r2 = r4.f     // Catch: java.lang.Throwable -> L8c
            okhttp3.a r2 = (okhttp3.C5072a) r2     // Catch: java.lang.Throwable -> L8c
            okhttp3.s r2 = r2.h     // Catch: java.lang.Throwable -> L8c
            boolean r0 = okhttp3.internal.b.a(r0, r2)     // Catch: java.lang.Throwable -> L8c
            if (r0 != 0) goto L88
            monitor-exit(r5)
            goto L8f
        L88:
            okhttp3.K r7 = r5.b     // Catch: java.lang.Throwable -> L8c
            monitor-exit(r5)
            goto L8f
        L8c:
            r4 = move-exception
            monitor-exit(r5)
            throw r4
        L8f:
            if (r7 == 0) goto L95
            r4.j = r7
        L93:
            r4 = r6
            goto Lad
        L95:
            java.lang.Object r5 = r4.h
            com.google.firebase.crashlytics.internal.metadata.p r5 = (com.google.firebase.crashlytics.internal.metadata.p) r5
            if (r5 == 0) goto La2
            boolean r5 = r5.c()
            if (r5 != r6) goto La2
            goto La8
        La2:
            java.lang.Object r4 = r4.i
            com.google.android.gms.internal.ads.ea r4 = (com.google.android.gms.internal.ads.C2007ea) r4
            if (r4 != 0) goto La9
        La8:
            goto L93
        La9:
            boolean r4 = r4.k()
        Lad:
            if (r4 != 0) goto Lb0
        Laf:
            return r1
        Lb0:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http.a.b(java.io.IOException, okhttp3.internal.connection.g, okhttp3.C, boolean):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x00cd, code lost:
    
        r6.g(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00db, code lost:
    
        return r9;
     */
    @Override // okhttp3.u
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final okhttp3.H intercept(okhttp3.t r31) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 740
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http.a.intercept(okhttp3.t):okhttp3.H");
    }

    public a(A client) {
        Intrinsics.checkNotNullParameter(client, "client");
        this.b = client;
    }
}
