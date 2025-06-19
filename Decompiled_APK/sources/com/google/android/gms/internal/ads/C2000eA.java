package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.text.TextUtils;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/* renamed from: com.google.android.gms.internal.ads.eA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2000eA extends AbstractC2802wu {
    public RandomAccessFile e;
    public Uri f;
    public long g;
    public boolean h;

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws IOException {
        Uri uri = c2891yx.a;
        this.f = uri;
        n(c2891yx);
        try {
            String path = uri.getPath();
            if (path == null) {
                throw null;
            }
            RandomAccessFile randomAccessFile = new RandomAccessFile(path, "r");
            this.e = randomAccessFile;
            try {
                long j = c2891yx.c;
                randomAccessFile.seek(j);
                long length = c2891yx.d;
                if (length == -1) {
                    length = this.e.length() - j;
                }
                this.g = length;
                if (length < 0) {
                    throw new zzgu(null, null, 2008);
                }
                this.h = true;
                p(c2891yx);
                return this.g;
            } catch (IOException e) {
                throw new zzgu(2000, e);
            }
        } catch (FileNotFoundException e2) {
            if (TextUtils.isEmpty(uri.getQuery()) && TextUtils.isEmpty(uri.getFragment())) {
                throw new zzgu(((e2.getCause() instanceof ErrnoException) && ((ErrnoException) e2.getCause()).errno == OsConstants.EACCES) ? 2006 : 2005, e2);
            }
            String path2 = uri.getPath();
            String query = uri.getQuery();
            String fragment = uri.getFragment();
            StringBuilder sbH = AbstractC0147y.h("uri has query and/or fragment, which are not supported. Did you call Uri.parse() on a string containing '?' or '#'? Use Uri.fromFile(new File(path)) to avoid this. path=", path2, ",query=", query, ",fragment=");
            sbH.append(fragment);
            throw new zzgu(sbH.toString(), e2, 1004);
        } catch (SecurityException e3) {
            throw new zzgu(2006, e3);
        } catch (RuntimeException e4) {
            throw new zzgu(2000, e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (i2 == 0) {
            return 0;
        }
        long j = this.g;
        if (j == 0) {
            return -1;
        }
        try {
            RandomAccessFile randomAccessFile = this.e;
            String str = Yo.a;
            int i3 = randomAccessFile.read(bArr, i, (int) Math.min(j, i2));
            if (i3 > 0) {
                this.g -= i3;
                e(i3);
            }
            return i3;
        } catch (IOException e) {
            throw new zzgu(2000, e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        this.f = null;
        try {
            try {
                RandomAccessFile randomAccessFile = this.e;
                if (randomAccessFile != null) {
                    randomAccessFile.close();
                }
                this.e = null;
                if (this.h) {
                    this.h = false;
                    b();
                }
            } catch (IOException e) {
                throw new zzgu(2000, e);
            }
        } catch (Throwable th) {
            this.e = null;
            if (this.h) {
                this.h = false;
                b();
            }
            throw th;
        }
    }
}
