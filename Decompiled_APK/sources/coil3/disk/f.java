package coil3.disk;

import androidx.navigation.U;
import com.google.android.gms.internal.ads.C2007ea;
import java.io.EOFException;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.E;
import okio.I;
import okio.p;
import okio.z;

/* loaded from: classes.dex */
public final class f implements E {
    public final /* synthetic */ int a = 1;
    public boolean b;
    public final Object c;
    public final Object d;

    public f(E e, U u) {
        this.c = e;
        this.d = u;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) throws EOFException {
        switch (this.a) {
            case 0:
                if (this.b) {
                    source.skip(j);
                    return;
                }
                try {
                    ((E) this.c).L(source, j);
                    return;
                } catch (IOException e) {
                    this.b = true;
                    ((U) this.d).invoke(e);
                    return;
                }
            default:
                Intrinsics.checkNotNullParameter(source, "source");
                if (this.b) {
                    throw new IllegalStateException("closed");
                }
                okhttp3.internal.b.c(source.b, 0L, j);
                ((z) ((C2007ea) this.d).e).L(source, j);
                return;
        }
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        switch (this.a) {
            case 0:
                try {
                    ((E) this.c).close();
                    break;
                } catch (IOException e) {
                    this.b = true;
                    ((U) this.d).invoke(e);
                    return;
                }
            default:
                if (!this.b) {
                    this.b = true;
                    C2007ea c2007ea = (C2007ea) this.d;
                    C2007ea.i(c2007ea, (p) this.c);
                    c2007ea.b = 3;
                    break;
                }
                break;
        }
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() {
        switch (this.a) {
            case 0:
                try {
                    ((E) this.c).flush();
                    break;
                } catch (IOException e) {
                    this.b = true;
                    ((U) this.d).invoke(e);
                    return;
                }
            default:
                if (!this.b) {
                    ((z) ((C2007ea) this.d).e).flush();
                    break;
                }
                break;
        }
    }

    @Override // okio.E
    public final I h() {
        switch (this.a) {
            case 0:
                return ((E) this.c).h();
            default:
                return (p) this.c;
        }
    }

    public f(C2007ea c2007ea) {
        this.d = c2007ea;
        this.c = new p(((z) c2007ea.e).a.h());
    }
}
