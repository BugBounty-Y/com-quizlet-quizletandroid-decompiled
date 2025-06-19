package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.net.Uri;
import android.text.TextUtils;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.fC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2046fC extends AbstractC2802wu {
    public final Context e;
    public C2891yx f;
    public AssetFileDescriptor g;
    public FileInputStream h;
    public long i;
    public boolean j;

    public C2046fC(Context context) {
        super(false);
        this.e = context.getApplicationContext();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        C2891yx c2891yx = this.f;
        if (c2891yx != null) {
            return c2891yx.a;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws Resources.NotFoundException, PackageManager.NameNotFoundException, NumberFormatException, zzgh {
        Resources resourcesForApplication;
        int identifier;
        Resources resources;
        long size;
        this.f = c2891yx;
        n(c2891yx);
        Uri uriNormalizeScheme = c2891yx.a.normalizeScheme();
        boolean zEquals = TextUtils.equals("rawresource", uriNormalizeScheme.getScheme());
        Context context = this.e;
        if (zEquals) {
            resources = context.getResources();
            List<String> pathSegments = uriNormalizeScheme.getPathSegments();
            if (pathSegments.size() != 1) {
                throw new zzhd(android.support.v4.media.session.a.f(pathSegments.size(), "rawresource:// URI must have exactly one path element, found "), null, 2000);
            }
            try {
                identifier = Integer.parseInt(pathSegments.get(0));
            } catch (NumberFormatException unused) {
                throw new zzhd("Resource identifier must be an integer.", null, 1004);
            }
        } else {
            if (!TextUtils.equals("android.resource", uriNormalizeScheme.getScheme())) {
                throw new zzhd(android.support.v4.media.session.a.B("Unsupported URI scheme (", uriNormalizeScheme.getScheme(), "). Only android.resource is supported."), null, 1004);
            }
            String path = uriNormalizeScheme.getPath();
            path.getClass();
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            String packageName = TextUtils.isEmpty(uriNormalizeScheme.getHost()) ? context.getPackageName() : uriNormalizeScheme.getHost();
            if (packageName.equals(context.getPackageName())) {
                resourcesForApplication = context.getResources();
            } else {
                try {
                    resourcesForApplication = context.getPackageManager().getResourcesForApplication(packageName);
                } catch (PackageManager.NameNotFoundException e) {
                    throw new zzhd("Package in android.resource:// URI not found. Check http://g.co/dev/packagevisibility.", e, 2005);
                }
            }
            if (path.matches("\\d+")) {
                try {
                    identifier = Integer.parseInt(path);
                } catch (NumberFormatException unused2) {
                    throw new zzhd("Resource identifier must be an integer.", null, 1004);
                }
            } else {
                identifier = resourcesForApplication.getIdentifier(android.support.v4.media.session.a.l(packageName, ":", path), "raw", null);
                if (identifier == 0) {
                    throw new zzhd("Resource not found.", null, 2005);
                }
            }
            resources = resourcesForApplication;
        }
        try {
            AssetFileDescriptor assetFileDescriptorOpenRawResourceFd = resources.openRawResourceFd(identifier);
            if (assetFileDescriptorOpenRawResourceFd == null) {
                throw new zzhd("Resource is compressed: ".concat(String.valueOf(uriNormalizeScheme)), null, 2000);
            }
            this.g = assetFileDescriptorOpenRawResourceFd;
            long length = assetFileDescriptorOpenRawResourceFd.getLength();
            FileInputStream fileInputStream = new FileInputStream(this.g.getFileDescriptor());
            this.h = fileInputStream;
            long j = c2891yx.c;
            try {
                if (length != -1 && j > length) {
                    throw new zzhd(null, null, 2008);
                }
                long startOffset = this.g.getStartOffset();
                long jSkip = fileInputStream.skip(startOffset + j) - startOffset;
                if (jSkip != j) {
                    throw new zzhd(null, null, 2008);
                }
                if (length == -1) {
                    FileChannel channel = fileInputStream.getChannel();
                    if (channel.size() == 0) {
                        this.i = -1L;
                        size = -1;
                    } else {
                        size = channel.size() - channel.position();
                        this.i = size;
                        if (size < 0) {
                            throw new zzhd(null, null, 2008);
                        }
                    }
                } else {
                    size = length - jSkip;
                    this.i = size;
                    if (size < 0) {
                        throw new zzgh();
                    }
                }
                long j2 = c2891yx.d;
                if (j2 != -1) {
                    this.i = size == -1 ? j2 : Math.min(size, j2);
                }
                this.j = true;
                p(c2891yx);
                return j2 != -1 ? j2 : this.i;
            } catch (zzhd e2) {
                throw e2;
            } catch (IOException e3) {
                throw new zzhd(null, e3, 2000);
            }
        } catch (Resources.NotFoundException e4) {
            throw new zzhd(null, e4, 2005);
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
                    throw new zzhd(null, e, 2000);
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
            if (this.i != -1) {
                throw new zzhd("End of stream reached having not read sufficient data.", new EOFException(), 2000);
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
                        throw new zzhd(null, e, 2000);
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
                        throw new zzhd(null, e2, 2000);
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
            throw new zzhd(null, e3, 2000);
        }
    }
}
