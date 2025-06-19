package okhttp3.internal.connection;

import androidx.compose.animation.d0;
import androidx.compose.material.ripple.r;
import java.io.IOException;
import java.net.ProtocolException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.E;
import okio.I;

/* loaded from: classes3.dex */
public final class b implements E {
    public final E a;
    public final long b;
    public boolean c;
    public long d;
    public boolean e;
    public final /* synthetic */ r f;

    public b(r rVar, E delegate, long j) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.f = rVar;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
        this.b = j;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.e) {
            throw new IllegalStateException("closed");
        }
        long j2 = this.b;
        if (j2 != -1 && this.d + j > j2) {
            StringBuilder sbT = d0.t(j2, "expected ", " bytes but received ");
            sbT.append(this.d + j);
            throw new ProtocolException(sbT.toString());
        }
        try {
            Intrinsics.checkNotNullParameter(source, "source");
            this.a.L(source, j);
            this.d += j;
        } catch (IOException e) {
            throw d(e);
        }
    }

    public final void a() {
        this.a.close();
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        if (this.e) {
            return;
        }
        this.e = true;
        long j = this.b;
        if (j != -1 && this.d != j) {
            throw new ProtocolException("unexpected end of stream");
        }
        try {
            a();
            d(null);
        } catch (IOException e) {
            throw d(e);
        }
    }

    public final IOException d(IOException iOException) {
        if (this.c) {
            return iOException;
        }
        this.c = true;
        return this.f.c(false, true, iOException);
    }

    public final void f() {
        this.a.flush();
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() throws IOException {
        try {
            f();
        } catch (IOException e) {
            throw d(e);
        }
    }

    @Override // okio.E
    public final I h() {
        return this.a.h();
    }

    public final String toString() {
        return b.class.getSimpleName() + '(' + this.a + ')';
    }
}
