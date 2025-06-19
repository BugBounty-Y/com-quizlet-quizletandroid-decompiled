package com.google.android.gms.internal.ads;

import android.graphics.SurfaceTexture;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.yd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2871yd {
    public final long a;
    public long b;
    public boolean c;

    public C2871yd(long j, long j2, boolean z) {
        this.a = j;
        this.b = j2;
        this.c = z;
    }

    public static C2871yd a(FileDescriptor fileDescriptor) throws IOException {
        try {
            StructStat structStatFstat = android.system.Os.fstat(fileDescriptor);
            return new C2871yd(structStatFstat.st_dev, structStatFstat.st_ino, OsConstants.S_ISLNK(structStatFstat.st_mode));
        } catch (Throwable th) {
            throw new IOException(th);
        }
    }

    public static C2871yd c(String str) throws IOException {
        try {
            StructStat structStatLstat = android.system.Os.lstat(str);
            return new C2871yd(structStatLstat.st_dev, structStatLstat.st_ino, OsConstants.S_ISLNK(structStatLstat.st_mode));
        } catch (Throwable th) {
            throw new IOException(th);
        }
    }

    public void b(SurfaceTexture surfaceTexture, C2785wd c2785wd) {
        if (c2785wd == null) {
            return;
        }
        long timestamp = surfaceTexture.getTimestamp();
        if (!this.c) {
            long j = timestamp - this.b;
            if (Math.abs(j) < this.a) {
                return;
            }
        }
        this.c = false;
        this.b = timestamp;
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2699ud(c2785wd, 3));
    }

    public C2871yd() {
        this.a = TimeUnit.MILLISECONDS.toNanos(((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K)).longValue());
        this.c = true;
    }
}
