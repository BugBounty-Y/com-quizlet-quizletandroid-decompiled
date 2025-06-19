package okio;

import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements E {
    public final s a;
    public long b;
    public boolean c;

    public l(s fileHandle) {
        Intrinsics.checkNotNullParameter(fileHandle, "fileHandle");
        this.a = fileHandle;
        this.b = 0L;
    }

    @Override // okio.E
    public final void L(C5091h source, long j) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        s sVar = this.a;
        long j2 = this.b;
        sVar.getClass();
        AbstractC5085b.e(source.b, 0L, j);
        long j3 = j2 + j;
        while (j2 < j3) {
            B b = source.a;
            Intrinsics.d(b);
            int iMin = (int) Math.min(j3 - j2, b.c - b.b);
            byte[] array = b.a;
            int i = b.b;
            synchronized (sVar) {
                Intrinsics.checkNotNullParameter(array, "array");
                sVar.e.seek(j2);
                sVar.e.write(array, i, iMin);
            }
            int i2 = b.b + iMin;
            b.b = i2;
            long j4 = iMin;
            j2 += j4;
            source.b -= j4;
            if (i2 == b.c) {
                source.a = b.a();
                C.a(b);
            }
        }
        this.b += j;
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        if (this.c) {
            return;
        }
        this.c = true;
        s sVar = this.a;
        ReentrantLock reentrantLock = sVar.d;
        reentrantLock.lock();
        try {
            int i = sVar.c - 1;
            sVar.c = i;
            if (i == 0 && sVar.b) {
                Unit unit = Unit.a;
                synchronized (sVar) {
                    sVar.e.close();
                }
            }
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        s sVar = this.a;
        synchronized (sVar) {
            sVar.e.getFD().sync();
        }
    }

    @Override // okio.E
    public final I h() {
        return I.d;
    }
}
