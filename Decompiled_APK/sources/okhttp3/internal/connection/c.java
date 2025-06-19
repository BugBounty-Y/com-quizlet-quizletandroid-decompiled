package okhttp3.internal.connection;

import androidx.compose.material.ripple.r;
import java.io.IOException;
import java.net.ProtocolException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.G;
import okio.o;

/* loaded from: classes3.dex */
public final class c extends o {
    public final long b;
    public long c;
    public boolean d;
    public boolean e;
    public boolean f;
    public final /* synthetic */ r g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(r rVar, G delegate, long j) {
        super(delegate);
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.g = rVar;
        this.b = j;
        this.d = true;
        if (j == 0) {
            a(null);
        }
    }

    public final IOException a(IOException iOException) {
        if (this.e) {
            return iOException;
        }
        this.e = true;
        r rVar = this.g;
        if (iOException == null && this.d) {
            this.d = false;
            rVar.getClass();
            g call = (g) rVar.b;
            Intrinsics.checkNotNullParameter(call, "call");
        }
        return rVar.c(true, false, iOException);
    }

    @Override // okio.o, okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (this.f) {
            throw new IllegalStateException("closed");
        }
        try {
            long jB0 = this.a.b0(sink, j);
            if (this.d) {
                this.d = false;
                r rVar = this.g;
                rVar.getClass();
                g call = (g) rVar.b;
                Intrinsics.checkNotNullParameter(call, "call");
            }
            if (jB0 == -1) {
                a(null);
                return -1L;
            }
            long j2 = this.c + jB0;
            long j3 = this.b;
            if (j3 == -1 || j2 <= j3) {
                this.c = j2;
                if (j2 == j3) {
                    a(null);
                }
                return jB0;
            }
            throw new ProtocolException("expected " + j3 + " bytes but received " + j2);
        } catch (IOException e) {
            throw a(e);
        }
    }

    @Override // okio.o, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        if (this.f) {
            return;
        }
        this.f = true;
        try {
            super.close();
            a(null);
        } catch (IOException e) {
            throw a(e);
        }
    }
}
