package com.google.android.gms.internal.ads;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.Bundle;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Rv extends AbstractC2802wu {
    public final ContentResolver e;
    public Uri f;
    public AssetFileDescriptor g;
    public FileInputStream h;
    public long i;
    public boolean j;

    public Rv(Context context) {
        super(false);
        this.e = context.getContentResolver();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws IOException {
        int i;
        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor;
        long jPosition;
        try {
            try {
                Uri uriNormalizeScheme = c2891yx.a.normalizeScheme();
                this.f = uriNormalizeScheme;
                n(c2891yx);
                boolean zEquals = Objects.equals(uriNormalizeScheme.getScheme(), "content");
                ContentResolver contentResolver = this.e;
                if (zEquals) {
                    Bundle bundle = new Bundle();
                    bundle.putBoolean("android.provider.extra.ACCEPT_ORIGINAL_MEDIA_FORMAT", true);
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openTypedAssetFileDescriptor(uriNormalizeScheme, "*/*", bundle);
                } else {
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uriNormalizeScheme, "r");
                }
                this.g = assetFileDescriptorOpenAssetFileDescriptor;
                if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                    i = 2000;
                    try {
                        throw new zzgc(2000, new IOException("Could not open file descriptor for: ".concat(String.valueOf(uriNormalizeScheme))));
                    } catch (IOException e) {
                        e = e;
                        throw new zzgc(true != (e instanceof FileNotFoundException) ? i : 2005, e);
                    }
                }
                long length = assetFileDescriptorOpenAssetFileDescriptor.getLength();
                FileInputStream fileInputStream = new FileInputStream(assetFileDescriptorOpenAssetFileDescriptor.getFileDescriptor());
                this.h = fileInputStream;
                long j = c2891yx.c;
                if (length != -1 && j > length) {
                    throw new zzgc(2008, null);
                }
                long startOffset = assetFileDescriptorOpenAssetFileDescriptor.getStartOffset();
                long jSkip = fileInputStream.skip(startOffset + j) - startOffset;
                if (jSkip != j) {
                    throw new zzgc(2008, null);
                }
                if (length == -1) {
                    FileChannel channel = fileInputStream.getChannel();
                    long size = channel.size();
                    if (size == 0) {
                        this.i = -1L;
                        jPosition = -1;
                    } else {
                        jPosition = size - channel.position();
                        this.i = jPosition;
                        if (jPosition < 0) {
                            throw new zzgc(2008, null);
                        }
                    }
                } else {
                    jPosition = length - jSkip;
                    this.i = jPosition;
                    if (jPosition < 0) {
                        throw new zzgc(2008, null);
                    }
                }
                long j2 = c2891yx.d;
                if (j2 != -1) {
                    this.i = jPosition == -1 ? j2 : Math.min(jPosition, j2);
                }
                this.j = true;
                p(c2891yx);
                return j2 != -1 ? j2 : this.i;
            } catch (IOException e2) {
                e = e2;
                i = 2000;
            }
        } catch (zzgc e3) {
            throw e3;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (i2 == 0) {
            return 0;
        }
        long j = this.i;
        if (j != 0) {
            if (j != -1) {
                try {
                    i2 = (int) Math.min(j, i2);
                } catch (IOException e) {
                    throw new zzgc(2000, e);
                }
            }
            FileInputStream fileInputStream = this.h;
            String str = Yo.a;
            int i3 = fileInputStream.read(bArr, i, i2);
            if (i3 != -1) {
                long j2 = this.i;
                if (j2 != -1) {
                    this.i = j2 - i3;
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
                try {
                    FileInputStream fileInputStream = this.h;
                    if (fileInputStream != null) {
                        fileInputStream.close();
                    }
                    this.h = null;
                    try {
                        AssetFileDescriptor assetFileDescriptor = this.g;
                        if (assetFileDescriptor != null) {
                            assetFileDescriptor.close();
                        }
                        this.g = null;
                        if (this.j) {
                            this.j = false;
                            b();
                        }
                    } catch (IOException e) {
                        throw new zzgc(2000, e);
                    }
                } catch (Throwable th) {
                    this.h = null;
                    try {
                        AssetFileDescriptor assetFileDescriptor2 = this.g;
                        if (assetFileDescriptor2 != null) {
                            assetFileDescriptor2.close();
                        }
                        this.g = null;
                        if (this.j) {
                            this.j = false;
                            b();
                        }
                        throw th;
                    } catch (IOException e2) {
                        throw new zzgc(2000, e2);
                    }
                }
            } catch (Throwable th2) {
                this.g = null;
                if (this.j) {
                    this.j = false;
                    b();
                }
                throw th2;
            }
        } catch (IOException e3) {
            throw new zzgc(2000, e3);
        }
    }
}
