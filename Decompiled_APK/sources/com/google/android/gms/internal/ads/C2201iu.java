package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/* renamed from: com.google.android.gms.internal.ads.iu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2201iu extends AbstractC2802wu {
    public final AssetManager e;
    public Uri f;
    public InputStream g;
    public long h;
    public boolean i;

    public C2201iu(Context context) {
        super(false);
        this.e = context.getAssets();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws IOException {
        try {
            Uri uri = c2891yx.a;
            this.f = uri;
            String path = uri.getPath();
            if (path == null) {
                throw null;
            }
            if (path.startsWith("/android_asset/")) {
                path = path.substring(15);
            } else if (path.startsWith("/")) {
                path = path.substring(1);
            }
            n(c2891yx);
            InputStream inputStreamOpen = this.e.open(path, 1);
            this.g = inputStreamOpen;
            long j = c2891yx.c;
            if (inputStreamOpen.skip(j) < j) {
                throw new zzfx(2008, null);
            }
            long j2 = c2891yx.d;
            if (j2 != -1) {
                this.h = j2;
            } else {
                long jAvailable = this.g.available();
                this.h = jAvailable;
                if (jAvailable == 2147483647L) {
                    this.h = -1L;
                }
            }
            this.i = true;
            p(c2891yx);
            return this.h;
        } catch (zzfx e) {
            throw e;
        } catch (IOException e2) {
            throw new zzfx(true != (e2 instanceof FileNotFoundException) ? 2000 : 2005, e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (i2 == 0) {
            return 0;
        }
        long j = this.h;
        if (j != 0) {
            if (j != -1) {
                try {
                    i2 = (int) Math.min(j, i2);
                } catch (IOException e) {
                    throw new zzfx(2000, e);
                }
            }
            InputStream inputStream = this.g;
            String str = Yo.a;
            int i3 = inputStream.read(bArr, i, i2);
            if (i3 != -1) {
                long j2 = this.h;
                if (j2 != -1) {
                    this.h = j2 - i3;
                }
                e(i3);
                return i3;
            }
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        this.f = null;
        try {
            try {
                InputStream inputStream = this.g;
                if (inputStream != null) {
                    inputStream.close();
                }
                this.g = null;
                if (this.i) {
                    this.i = false;
                    b();
                }
            } catch (IOException e) {
                throw new zzfx(2000, e);
            }
        } catch (Throwable th) {
            this.g = null;
            if (this.i) {
                this.i = false;
                b();
            }
            throw th;
        }
    }
}
