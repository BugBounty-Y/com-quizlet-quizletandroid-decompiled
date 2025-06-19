package okhttp3.internal.http2;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.features.folders.composables.W;
import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.A;

/* loaded from: classes3.dex */
public final class r implements Closeable, AutoCloseable {
    public static final Logger d;
    public final A a;
    public final q b;
    public final androidx.compose.ui.text.caches.b c;

    static {
        Logger logger = Logger.getLogger(e.class.getName());
        Intrinsics.checkNotNullExpressionValue(logger, "getLogger(Http2::class.java.name)");
        d = logger;
    }

    public r(A source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        q qVar = new q(source);
        this.b = qVar;
        this.c = new androidx.compose.ui.text.caches.b(qVar);
    }

    /* JADX WARN: Code restructure failed: missing block: B:142:0x0253, code lost:
    
        throw new java.io.IOException(android.support.v4.media.session.a.f(r8, "PROTOCOL_ERROR SETTINGS_MAX_FRAME_SIZE: "));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(boolean r20, com.quizlet.features.folders.composables.W r21) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 920
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.r.a(boolean, com.quizlet.features.folders.composables.W):boolean");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.a.close();
    }

    /* JADX WARN: Code restructure failed: missing block: B:68:0x013b, code lost:
    
        if (r8 == false) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x013d, code lost:
    
        r16.i(okhttp3.internal.b.b, true);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.quizlet.features.folders.composables.W r18, int r19, int r20, int r21) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 348
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.r.d(com.quizlet.features.folders.composables.W, int, int, int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x006d, code lost:
    
        throw new java.io.IOException(android.support.v4.media.session.a.f(r7, "Header index too large "));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List f(int r6, int r7, int r8, int r9) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 311
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.r.f(int, int, int, int):java.util.List");
    }

    public final void i(W w, int i, int i2, int i3) throws IOException {
        int i4;
        int i5 = 1;
        if (i3 == 0) {
            throw new IOException("PROTOCOL_ERROR: TYPE_HEADERS streamId == 0");
        }
        boolean z = false;
        boolean z2 = (i2 & 1) != 0;
        if ((i2 & 8) != 0) {
            byte b = this.a.readByte();
            byte[] bArr = okhttp3.internal.b.a;
            i4 = b & 255;
        } else {
            i4 = 0;
        }
        if ((i2 & 32) != 0) {
            A a = this.a;
            a.i();
            a.readByte();
            byte[] bArr2 = okhttp3.internal.b.a;
            i -= 5;
        }
        List requestHeaders = f(p.a(i, i2, i4), i4, i2, i3);
        Intrinsics.checkNotNullParameter(requestHeaders, "headerBlock");
        ((n) w.c).getClass();
        if (i3 != 0 && (i3 & 1) == 0) {
            z = true;
        }
        if (z) {
            n nVar = (n) w.c;
            nVar.getClass();
            Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
            nVar.i.c(new k(nVar.c + '[' + i3 + "] onHeaders", nVar, i3, requestHeaders, z2), 0L);
            return;
        }
        n nVar2 = (n) w.c;
        synchronized (nVar2) {
            v vVarF = nVar2.f(i3);
            if (vVarF != null) {
                Unit unit = Unit.a;
                vVarF.i(okhttp3.internal.b.w(requestHeaders), z2);
                return;
            }
            if (nVar2.f) {
                return;
            }
            if (i3 <= nVar2.d) {
                return;
            }
            if (i3 % 2 == nVar2.e % 2) {
                return;
            }
            v vVar = new v(i3, nVar2, false, z2, okhttp3.internal.b.w(requestHeaders));
            nVar2.d = i3;
            nVar2.b.put(Integer.valueOf(i3), vVar);
            nVar2.g.e().c(new h(i5, nVar2, vVar, nVar2.c + '[' + i3 + "] onStream"), 0L);
        }
    }

    public final void j(W w, int i, int i2, int i3) throws IOException {
        int i4;
        if (i3 == 0) {
            throw new IOException("PROTOCOL_ERROR: TYPE_PUSH_PROMISE streamId == 0");
        }
        if ((i2 & 8) != 0) {
            byte b = this.a.readByte();
            byte[] bArr = okhttp3.internal.b.a;
            i4 = b & 255;
        } else {
            i4 = 0;
        }
        int i5 = this.a.i() & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        List requestHeaders = f(p.a(i - 4, i2, i4), i4, i2, i3);
        Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
        n nVar = (n) w.c;
        nVar.getClass();
        Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
        synchronized (nVar) {
            if (nVar.y.contains(Integer.valueOf(i5))) {
                nVar.q(i5, a.PROTOCOL_ERROR);
                return;
            }
            nVar.y.add(Integer.valueOf(i5));
            nVar.i.c(new k(nVar.c + '[' + i5 + "] onRequest", nVar, i5, requestHeaders), 0L);
        }
    }
}
