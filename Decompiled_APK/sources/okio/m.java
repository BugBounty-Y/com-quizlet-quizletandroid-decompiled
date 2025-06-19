package okio;

import androidx.compose.animation.d0;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements G {
    public final s a;
    public long b;
    public boolean c;

    public m(s fileHandle, long j) {
        Intrinsics.checkNotNullParameter(fileHandle, "fileHandle");
        this.a = fileHandle;
        this.b = j;
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) {
        long j2;
        long j3;
        int i;
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        s sVar = this.a;
        long j4 = this.b;
        sVar.getClass();
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        long j5 = j + j4;
        long j6 = j4;
        while (true) {
            if (j6 >= j5) {
                j2 = -1;
                break;
            }
            B bL0 = sink.l0(1);
            byte[] array = bL0.a;
            int i2 = bL0.c;
            j2 = -1;
            int iMin = (int) Math.min(j5 - j6, 8192 - i2);
            synchronized (sVar) {
                Intrinsics.checkNotNullParameter(array, "array");
                sVar.e.seek(j6);
                i = 0;
                while (true) {
                    if (i >= iMin) {
                        break;
                    }
                    int i3 = sVar.e.read(array, i2, iMin - i);
                    if (i3 != -1) {
                        i += i3;
                    } else if (i == 0) {
                        i = -1;
                    }
                }
            }
            if (i == -1) {
                if (bL0.b == bL0.c) {
                    sink.a = bL0.a();
                    C.a(bL0);
                }
                if (j4 == j6) {
                    j3 = -1;
                }
            } else {
                bL0.c += i;
                long j7 = i;
                j6 += j7;
                sink.b += j7;
            }
        }
        j3 = j6 - j4;
        if (j3 != j2) {
            this.b += j3;
        }
        return j3;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
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

    @Override // okio.G
    public final I h() {
        return I.d;
    }
}
