package com.bumptech.glide.load.resource.bitmap;

import android.util.Log;
import androidx.appcompat.app.Q;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;

/* loaded from: classes.dex */
public final class l implements com.bumptech.glide.load.d {
    public static final byte[] a = "Exif\u0000\u0000".getBytes(Charset.forName("UTF-8"));
    public static final int[] b = {0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8};

    public static int e(k kVar, androidx.compose.foundation.lazy.grid.m mVar) {
        int iB;
        try {
            int iB2 = kVar.b();
            if (!((iB2 & 65496) == 65496 || iB2 == 19789 || iB2 == 18761)) {
                Log.isLoggable("DfltImageHeaderParser", 3);
                return -1;
            }
            while (true) {
                if (kVar.o() == 255) {
                    short sO = kVar.o();
                    if (sO == 218) {
                        break;
                    }
                    if (sO != 217) {
                        iB = kVar.b() - 2;
                        if (sO == 225) {
                            break;
                        }
                        long j = iB;
                        if (kVar.skip(j) != j) {
                            Log.isLoggable("DfltImageHeaderParser", 3);
                            break;
                        }
                    } else {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                        break;
                    }
                } else {
                    Log.isLoggable("DfltImageHeaderParser", 3);
                    break;
                }
            }
            iB = -1;
            if (iB == -1) {
                Log.isLoggable("DfltImageHeaderParser", 3);
                return -1;
            }
            byte[] bArr = (byte[]) mVar.f(iB, byte[].class);
            try {
                return g(kVar, bArr, iB);
            } finally {
                mVar.k(bArr);
            }
        } catch (DefaultImageHeaderParser$Reader$EndOfFileException unused) {
            return -1;
        }
    }

    public static ImageHeaderParser$ImageType f(k kVar) {
        try {
            int iB = kVar.b();
            if (iB == 65496) {
                return ImageHeaderParser$ImageType.JPEG;
            }
            int iO = (iB << 8) | kVar.o();
            if (iO == 4671814) {
                return ImageHeaderParser$ImageType.GIF;
            }
            int iO2 = (iO << 8) | kVar.o();
            if (iO2 == -1991225785) {
                kVar.skip(21L);
                try {
                    return kVar.o() >= 3 ? ImageHeaderParser$ImageType.PNG_A : ImageHeaderParser$ImageType.PNG;
                } catch (DefaultImageHeaderParser$Reader$EndOfFileException unused) {
                    return ImageHeaderParser$ImageType.PNG;
                }
            }
            if (iO2 == 1380533830) {
                kVar.skip(4L);
                if (((kVar.b() << 16) | kVar.b()) != 1464156752) {
                    return ImageHeaderParser$ImageType.UNKNOWN;
                }
                int iB2 = (kVar.b() << 16) | kVar.b();
                if ((iB2 & (-256)) != 1448097792) {
                    return ImageHeaderParser$ImageType.UNKNOWN;
                }
                int i = iB2 & 255;
                if (i == 88) {
                    kVar.skip(4L);
                    short sO = kVar.o();
                    return (sO & 2) != 0 ? ImageHeaderParser$ImageType.ANIMATED_WEBP : (sO & 16) != 0 ? ImageHeaderParser$ImageType.WEBP_A : ImageHeaderParser$ImageType.WEBP;
                }
                if (i != 76) {
                    return ImageHeaderParser$ImageType.WEBP;
                }
                kVar.skip(4L);
                return (kVar.o() & 8) != 0 ? ImageHeaderParser$ImageType.WEBP_A : ImageHeaderParser$ImageType.WEBP;
            }
            if (((kVar.b() << 16) | kVar.b()) != 1718909296) {
                return ImageHeaderParser$ImageType.UNKNOWN;
            }
            int iB3 = (kVar.b() << 16) | kVar.b();
            if (iB3 == 1635150195) {
                return ImageHeaderParser$ImageType.ANIMATED_AVIF;
            }
            int i2 = 0;
            boolean z = iB3 == 1635150182;
            kVar.skip(4L);
            int i3 = iO2 - 16;
            if (i3 % 4 == 0) {
                while (i2 < 5 && i3 > 0) {
                    int iB4 = (kVar.b() << 16) | kVar.b();
                    if (iB4 == 1635150195) {
                        return ImageHeaderParser$ImageType.ANIMATED_AVIF;
                    }
                    if (iB4 == 1635150182) {
                        z = true;
                    }
                    i2++;
                    i3 -= 4;
                }
            }
            return z ? ImageHeaderParser$ImageType.AVIF : ImageHeaderParser$ImageType.UNKNOWN;
        } catch (DefaultImageHeaderParser$Reader$EndOfFileException unused2) {
            return ImageHeaderParser$ImageType.UNKNOWN;
        }
    }

    public static int g(k kVar, byte[] bArr, int i) {
        ByteOrder byteOrder;
        if (kVar.s(i, bArr) != i) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            return -1;
        }
        byte[] bArr2 = a;
        boolean z = bArr != null && i > bArr2.length;
        if (z) {
            int i2 = 0;
            while (true) {
                if (i2 >= bArr2.length) {
                    break;
                }
                if (bArr[i2] != bArr2[i2]) {
                    z = false;
                    break;
                }
                i2++;
            }
        }
        if (!z) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            return -1;
        }
        ByteBuffer byteBuffer = (ByteBuffer) ByteBuffer.wrap(bArr).order(ByteOrder.BIG_ENDIAN).limit(i);
        short s = byteBuffer.remaining() - 6 >= 2 ? byteBuffer.getShort(6) : (short) -1;
        if (s == 18761) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (s != 19789) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else {
            byteOrder = ByteOrder.BIG_ENDIAN;
        }
        byteBuffer.order(byteOrder);
        int i3 = byteBuffer.remaining() - 10 >= 4 ? byteBuffer.getInt(10) : -1;
        int i4 = i3 + 6;
        short s2 = byteBuffer.remaining() - i4 >= 2 ? byteBuffer.getShort(i4) : (short) -1;
        for (int i5 = 0; i5 < s2; i5++) {
            int i6 = (i5 * 12) + i3 + 8;
            if ((byteBuffer.remaining() - i6 >= 2 ? byteBuffer.getShort(i6) : (short) -1) == 274) {
                int i7 = i6 + 2;
                short s3 = byteBuffer.remaining() - i7 >= 2 ? byteBuffer.getShort(i7) : (short) -1;
                if (s3 < 1 || s3 > 12) {
                    Log.isLoggable("DfltImageHeaderParser", 3);
                } else {
                    int i8 = i6 + 4;
                    int i9 = byteBuffer.remaining() - i8 >= 4 ? byteBuffer.getInt(i8) : -1;
                    if (i9 < 0) {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                    } else {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                        int i10 = i9 + b[s3];
                        if (i10 > 4) {
                            Log.isLoggable("DfltImageHeaderParser", 3);
                        } else {
                            int i11 = i6 + 8;
                            if (i11 < 0 || i11 > byteBuffer.remaining()) {
                                Log.isLoggable("DfltImageHeaderParser", 3);
                            } else {
                                if (i10 >= 0 && i10 + i11 <= byteBuffer.remaining()) {
                                    if (byteBuffer.remaining() - i11 >= 2) {
                                        return byteBuffer.getShort(i11);
                                    }
                                    return -1;
                                }
                                Log.isLoggable("DfltImageHeaderParser", 3);
                            }
                        }
                    }
                }
            }
        }
        return -1;
    }

    @Override // com.bumptech.glide.load.d
    public final ImageHeaderParser$ImageType a(ByteBuffer byteBuffer) {
        com.bumptech.glide.util.f.c(byteBuffer, "Argument must not be null");
        return f(new Q(byteBuffer));
    }

    @Override // com.bumptech.glide.load.d
    public final int b(InputStream inputStream, androidx.compose.foundation.lazy.grid.m mVar) {
        androidx.webkit.internal.p pVar = new androidx.webkit.internal.p(inputStream, 13);
        com.bumptech.glide.util.f.c(mVar, "Argument must not be null");
        return e(pVar, mVar);
    }

    @Override // com.bumptech.glide.load.d
    public final ImageHeaderParser$ImageType c(InputStream inputStream) {
        return f(new androidx.webkit.internal.p(inputStream, 13));
    }

    @Override // com.bumptech.glide.load.d
    public final int d(ByteBuffer byteBuffer, androidx.compose.foundation.lazy.grid.m mVar) {
        Q q = new Q(byteBuffer);
        com.bumptech.glide.util.f.c(mVar, "Argument must not be null");
        return e(q, mVar);
    }
}
