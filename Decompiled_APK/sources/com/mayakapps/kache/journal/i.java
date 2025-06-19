package com.mayakapps.kache.journal;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.mayakapps.kache.x;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.nio.channels.Channel;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import kotlin.G;
import kotlin.H;
import kotlin.jvm.internal.Intrinsics;
import kotlin.w;
import okio.A;
import okio.z;

/* loaded from: classes2.dex */
public final class i implements Closeable, AutoCloseable {
    public final /* synthetic */ int a = 0;
    public final int b;
    public final x c;
    public final Channel d;

    public i(A source, int i, x strategy) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(strategy, "strategy");
        this.d = source;
        this.b = i;
        this.c = strategy;
    }

    public h a() throws JournalInvalidOpcodeException, EOFException {
        A a = (A) this.d;
        String strR = null;
        try {
            byte b = a.readByte();
            short sP = a.p();
            G g = H.b;
            String key = a.r(sP & 65535);
            if (b == 33) {
                byte b2 = a.readByte();
                w wVar = kotlin.x.b;
                strR = a.r(b2 & 255);
            }
            Intrinsics.checkNotNullParameter(key, "key");
            if (b == 16) {
                return new e(key);
            }
            if (b == 32) {
                return new c(key);
            }
            if (b == 33) {
                Intrinsics.d(strR);
                return new d(key, strR);
            }
            if (b == 48) {
                return new b(key);
            }
            if (b == 64) {
                return new g(key);
            }
            if (b == 80) {
                return new f(key);
            }
            throw new JournalInvalidOpcodeException();
        } catch (EOFException unused) {
            return null;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        switch (this.a) {
            case 0:
                ((A) this.d).close();
                break;
            default:
                ((z) this.d).close();
                break;
        }
    }

    public void d() throws JournalInvalidHeaderException, EOFException {
        A a = (A) this.d;
        try {
            String strR = a.r(7L);
            if (!strR.equals("JOURNAL")) {
                throw new JournalInvalidHeaderException(android.support.v4.media.session.a.B("Journal magic (", strR, ") doesn't match"));
            }
            byte b = a.readByte();
            if (b != 4) {
                throw new JournalInvalidHeaderException(AbstractC0147y.c(b, "Journal version (", ") doesn't match"));
            }
            int i = a.i();
            int i2 = this.b;
            if (i2 != i) {
                throw new JournalInvalidHeaderException("Existing cache version (" + i + ") doesn't match current version (" + i2 + ')');
            }
            byte b2 = a.readByte();
            x xVar = this.c;
            if (xVar.ordinal() == b2) {
                return;
            }
            StringBuilder sbV = android.support.v4.media.session.a.v(b2, "Existing strategy (", ") doesn't match current strategy (");
            sbV.append(xVar.ordinal());
            sbV.append(')');
            throw new JournalInvalidHeaderException(sbV.toString());
        } catch (EOFException unused) {
            throw new JournalInvalidHeaderException("File size is less than journal magic code size");
        }
    }

    public void f(Map cleanKeys, Collection dirtyKeys) {
        Intrinsics.checkNotNullParameter(cleanKeys, "cleanKeys");
        Intrinsics.checkNotNullParameter(dirtyKeys, "dirtyKeys");
        for (Map.Entry entry : cleanKeys.entrySet()) {
            i((byte) 33, (String) entry.getKey(), (String) entry.getValue());
        }
        Iterator it2 = dirtyKeys.iterator();
        while (it2.hasNext()) {
            i((byte) 16, (String) it2.next(), null);
        }
        ((z) this.d).flush();
    }

    public void i(byte b, String str, String str2) {
        z zVar = (z) this.d;
        zVar.v(b);
        zVar.f(str.length());
        zVar.H(str);
        if (str2 != null) {
            zVar.v(str2.length());
            zVar.H(str2);
        }
    }

    public i(z sink) {
        x strategy = x.a;
        Intrinsics.checkNotNullParameter(sink, "sink");
        Intrinsics.checkNotNullParameter(strategy, "strategy");
        this.d = sink;
        this.b = 1;
        this.c = strategy;
    }
}
