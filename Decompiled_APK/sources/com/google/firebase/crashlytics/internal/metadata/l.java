package com.google.firebase.crashlytics.internal.metadata;

import androidx.appcompat.app.K;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.NoSuchElementException;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class l implements Closeable, AutoCloseable {
    public static final Logger g = Logger.getLogger(l.class.getName());
    public final RandomAccessFile a;
    public int b;
    public int c;
    public i d;
    public i e;
    public final byte[] f;

    public l(File file) throws IOException {
        byte[] bArr = new byte[16];
        this.f = bArr;
        if (!file.exists()) {
            File file2 = new File(file.getPath() + ".tmp");
            RandomAccessFile randomAccessFile = new RandomAccessFile(file2, "rwd");
            try {
                randomAccessFile.setLength(4096L);
                randomAccessFile.seek(0L);
                byte[] bArr2 = new byte[16];
                int[] iArr = {4096, 0, 0, 0};
                int i = 0;
                for (int i2 = 0; i2 < 4; i2++) {
                    D(i, bArr2, iArr[i2]);
                    i += 4;
                }
                randomAccessFile.write(bArr2);
                randomAccessFile.close();
                if (!file2.renameTo(file)) {
                    throw new IOException("Rename failed!");
                }
            } catch (Throwable th) {
                randomAccessFile.close();
                throw th;
            }
        }
        RandomAccessFile randomAccessFile2 = new RandomAccessFile(file, "rwd");
        this.a = randomAccessFile2;
        randomAccessFile2.seek(0L);
        randomAccessFile2.readFully(bArr);
        int iL = l(0, bArr);
        this.b = iL;
        if (iL > randomAccessFile2.length()) {
            throw new IOException("File is truncated. Expected length: " + this.b + ", Actual length: " + randomAccessFile2.length());
        }
        this.c = l(4, bArr);
        int iL2 = l(8, bArr);
        int iL3 = l(12, bArr);
        this.d = j(iL2);
        this.e = j(iL3);
    }

    public static void D(int i, byte[] bArr, int i2) {
        bArr[i] = (byte) (i2 >> 24);
        bArr[i + 1] = (byte) (i2 >> 16);
        bArr[i + 2] = (byte) (i2 >> 8);
        bArr[i + 3] = (byte) i2;
    }

    public static int l(int i, byte[] bArr) {
        return ((bArr[i] & 255) << 24) + ((bArr[i + 1] & 255) << 16) + ((bArr[i + 2] & 255) << 8) + (bArr[i + 3] & 255);
    }

    public final int B(int i) {
        int i2 = this.b;
        return i < i2 ? i : (i + 16) - i2;
    }

    public final void C(int i, int i2, int i3, int i4) throws IOException {
        int[] iArr = {i, i2, i3, i4};
        byte[] bArr = this.f;
        int i5 = 0;
        for (int i6 = 0; i6 < 4; i6++) {
            D(i5, bArr, iArr[i6]);
            i5 += 4;
        }
        RandomAccessFile randomAccessFile = this.a;
        randomAccessFile.seek(0L);
        randomAccessFile.write(bArr);
    }

    public final void a(byte[] bArr) {
        int iB;
        int length = bArr.length;
        synchronized (this) {
            if (length >= 0) {
                if (length <= bArr.length) {
                    d(length);
                    boolean zI = i();
                    if (zI) {
                        iB = 16;
                    } else {
                        i iVar = this.e;
                        iB = B(iVar.a + 4 + iVar.b);
                    }
                    i iVar2 = new i(iB, length);
                    D(0, this.f, length);
                    r(iB, this.f, 4);
                    r(iB + 4, bArr, length);
                    C(this.b, this.c + 1, zI ? iB : this.d.a, iB);
                    this.e = iVar2;
                    this.c++;
                    if (zI) {
                        this.d = iVar2;
                    }
                }
            }
            throw new IndexOutOfBoundsException();
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final synchronized void close() {
        this.a.close();
    }

    public final void d(int i) throws IOException {
        int i2 = i + 4;
        int iY = this.b - y();
        if (iY >= i2) {
            return;
        }
        int i3 = this.b;
        do {
            iY += i3;
            i3 <<= 1;
        } while (iY < i2);
        RandomAccessFile randomAccessFile = this.a;
        randomAccessFile.setLength(i3);
        randomAccessFile.getChannel().force(true);
        i iVar = this.e;
        int iB = B(iVar.a + 4 + iVar.b);
        if (iB < this.d.a) {
            FileChannel channel = randomAccessFile.getChannel();
            channel.position(this.b);
            long j = iB - 4;
            if (channel.transferTo(16L, j, channel) != j) {
                throw new AssertionError("Copied insufficient number of bytes!");
            }
        }
        int i4 = this.e.a;
        int i5 = this.d.a;
        if (i4 < i5) {
            int i6 = (this.b + i4) - 16;
            C(i3, this.c, i5, i6);
            this.e = new i(i6, this.e.b);
        } else {
            C(i3, this.c, i5, i4);
        }
        this.b = i3;
    }

    public final synchronized void f(k kVar) {
        int iB = this.d.a;
        for (int i = 0; i < this.c; i++) {
            i iVarJ = j(iB);
            kVar.a(new j(this, iVarJ), iVarJ.b);
            iB = B(iVarJ.a + 4 + iVarJ.b);
        }
    }

    public final synchronized boolean i() {
        return this.c == 0;
    }

    public final i j(int i) throws IOException {
        if (i == 0) {
            return i.c;
        }
        RandomAccessFile randomAccessFile = this.a;
        randomAccessFile.seek(i);
        return new i(i, randomAccessFile.readInt());
    }

    public final synchronized void p() {
        if (i()) {
            throw new NoSuchElementException();
        }
        if (this.c == 1) {
            synchronized (this) {
                C(4096, 0, 0, 0);
                this.c = 0;
                i iVar = i.c;
                this.d = iVar;
                this.e = iVar;
                if (this.b > 4096) {
                    RandomAccessFile randomAccessFile = this.a;
                    randomAccessFile.setLength(4096);
                    randomAccessFile.getChannel().force(true);
                }
                this.b = 4096;
            }
        } else {
            i iVar2 = this.d;
            int iB = B(iVar2.a + 4 + iVar2.b);
            q(iB, 0, this.f, 4);
            int iL = l(0, this.f);
            C(this.b, this.c - 1, iB, this.e.a);
            this.c--;
            this.d = new i(iB, iL);
        }
    }

    public final void q(int i, int i2, byte[] bArr, int i3) throws IOException {
        int iB = B(i);
        int i4 = iB + i3;
        int i5 = this.b;
        RandomAccessFile randomAccessFile = this.a;
        if (i4 <= i5) {
            randomAccessFile.seek(iB);
            randomAccessFile.readFully(bArr, i2, i3);
            return;
        }
        int i6 = i5 - iB;
        randomAccessFile.seek(iB);
        randomAccessFile.readFully(bArr, i2, i6);
        randomAccessFile.seek(16L);
        randomAccessFile.readFully(bArr, i2 + i6, i3 - i6);
    }

    public final void r(int i, byte[] bArr, int i2) throws IOException {
        int iB = B(i);
        int i3 = iB + i2;
        int i4 = this.b;
        RandomAccessFile randomAccessFile = this.a;
        if (i3 <= i4) {
            randomAccessFile.seek(iB);
            randomAccessFile.write(bArr, 0, i2);
            return;
        }
        int i5 = i4 - iB;
        randomAccessFile.seek(iB);
        randomAccessFile.write(bArr, 0, i5);
        randomAccessFile.seek(16L);
        randomAccessFile.write(bArr, i5, i2 - i5);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(l.class.getSimpleName());
        sb.append("[fileLength=");
        sb.append(this.b);
        sb.append(", size=");
        sb.append(this.c);
        sb.append(", first=");
        sb.append(this.d);
        sb.append(", last=");
        sb.append(this.e);
        sb.append(", element lengths=[");
        try {
            K k = new K();
            k.b = sb;
            k.a = true;
            f(k);
        } catch (IOException e) {
            g.log(Level.WARNING, "read error", (Throwable) e);
        }
        sb.append("]]");
        return sb.toString();
    }

    public final int y() {
        if (this.c == 0) {
            return 16;
        }
        i iVar = this.e;
        int i = iVar.a;
        int i2 = this.d.a;
        return i >= i2 ? (i - i2) + 4 + iVar.b + 16 : (((i + 4) + iVar.b) + this.b) - i2;
    }
}
