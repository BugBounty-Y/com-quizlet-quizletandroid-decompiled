package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Bitmap;
import android.media.Image;
import android.media.MediaCodec;
import android.net.Uri;
import androidx.appcompat.widget.C0122z;
import androidx.camera.core.impl.C0186z;
import androidx.fragment.app.Fragment;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.C3160h5;
import com.google.android.gms.internal.mlkit_vision_barcode.C3196l5;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3151g5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3282v5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.xF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2824xF implements com.google.android.gms.internal.mlkit_vision_barcode.I7 {
    public long a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public static void c(File file) {
        try {
            int iC = new androidx.exifinterface.media.h(file.getAbsolutePath()).c(0, "Orientation");
            com.facebook.appevents.ml.f.n(file);
            Set set = com.quizlet.qutils.image.capture.c.a;
            Intrinsics.checkNotNullParameter(file, "<this>");
            Set set2 = com.quizlet.qutils.image.capture.c.a;
            if ((set2 instanceof Collection) && set2.isEmpty()) {
                return;
            }
            Iterator it2 = set2.iterator();
            while (it2.hasNext()) {
                if (kotlin.text.D.l((String) it2.next(), kotlin.io.k.f(file), true)) {
                    androidx.exifinterface.media.h hVar = new androidx.exifinterface.media.h(file.getAbsolutePath());
                    hVar.E("Orientation", String.valueOf(iC));
                    hVar.A();
                    return;
                }
            }
        } catch (IOException e) {
            timber.log.c.a(e);
        }
    }

    public static androidx.compose.foundation.lazy.layout.p0 g(androidx.compose.foundation.lazy.layout.p0 p0Var, long j, ByteBuffer byteBuffer, int i) {
        while (j >= p0Var.b) {
            p0Var = (androidx.compose.foundation.lazy.layout.p0) p0Var.d;
        }
        while (i > 0) {
            int iMin = Math.min(i, (int) (p0Var.b - j));
            ZF zf = (ZF) p0Var.c;
            byte[] bArr = zf.a;
            long j2 = j - p0Var.a;
            zf.getClass();
            byteBuffer.put(bArr, (int) j2, iMin);
            i -= iMin;
            j += iMin;
            if (j == p0Var.b) {
                p0Var = (androidx.compose.foundation.lazy.layout.p0) p0Var.d;
            }
        }
        return p0Var;
    }

    public static androidx.compose.foundation.lazy.layout.p0 h(androidx.compose.foundation.lazy.layout.p0 p0Var, long j, byte[] bArr, int i) {
        while (j >= p0Var.b) {
            p0Var = (androidx.compose.foundation.lazy.layout.p0) p0Var.d;
        }
        int i2 = i;
        while (i2 > 0) {
            int iMin = Math.min(i2, (int) (p0Var.b - j));
            ZF zf = (ZF) p0Var.c;
            byte[] bArr2 = zf.a;
            long j2 = j - p0Var.a;
            zf.getClass();
            System.arraycopy(bArr2, (int) j2, bArr, i - i2, iMin);
            i2 -= iMin;
            j += iMin;
            if (j == p0Var.b) {
                p0Var = (androidx.compose.foundation.lazy.layout.p0) p0Var.d;
            }
        }
        return p0Var;
    }

    public static androidx.compose.foundation.lazy.layout.p0 i(androidx.compose.foundation.lazy.layout.p0 p0Var, MC mc, C0186z c0186z, Kn kn) {
        int iD;
        if (mc.s(1073741824)) {
            long j = c0186z.c;
            kn.g(1);
            androidx.compose.foundation.lazy.layout.p0 p0VarH = h(p0Var, j, kn.a, 1);
            long j2 = j + 1;
            byte b = kn.a[0];
            int i = b & 128;
            int i2 = b & Byte.MAX_VALUE;
            LC lc = mc.d;
            byte[] bArr = lc.a;
            if (bArr == null) {
                lc.a = new byte[16];
            } else {
                Arrays.fill(bArr, (byte) 0);
            }
            boolean z = i != 0;
            p0Var = h(p0VarH, j2, lc.a, i2);
            long j3 = j2 + i2;
            if (z) {
                kn.g(2);
                p0Var = h(p0Var, j3, kn.a, 2);
                j3 += 2;
                iD = kn.D();
            } else {
                iD = 1;
            }
            int[] iArr = lc.d;
            if (iArr == null || iArr.length < iD) {
                iArr = new int[iD];
            }
            int[] iArr2 = lc.e;
            if (iArr2 == null || iArr2.length < iD) {
                iArr2 = new int[iD];
            }
            if (z) {
                int i3 = iD * 6;
                kn.g(i3);
                p0Var = h(p0Var, j3, kn.a, i3);
                j3 += i3;
                kn.j(0);
                for (int i4 = 0; i4 < iD; i4++) {
                    iArr[i4] = kn.D();
                    iArr2[i4] = kn.C();
                }
            } else {
                iArr[0] = 0;
                iArr2[0] = c0186z.b - ((int) (j3 - c0186z.c));
            }
            C2337m0 c2337m0 = (C2337m0) c0186z.d;
            String str = Yo.a;
            byte[] bArr2 = c2337m0.b;
            byte[] bArr3 = lc.a;
            lc.f = iD;
            lc.d = iArr;
            lc.e = iArr2;
            lc.b = bArr2;
            lc.a = bArr3;
            int i5 = c2337m0.a;
            lc.c = i5;
            int i6 = c2337m0.c;
            lc.g = i6;
            int i7 = c2337m0.d;
            lc.h = i7;
            MediaCodec.CryptoInfo cryptoInfo = lc.i;
            cryptoInfo.numSubSamples = iD;
            cryptoInfo.numBytesOfClearData = iArr;
            cryptoInfo.numBytesOfEncryptedData = iArr2;
            cryptoInfo.key = bArr2;
            cryptoInfo.iv = bArr3;
            cryptoInfo.mode = i5;
            Fp fp = lc.j;
            fp.getClass();
            MediaCodec.CryptoInfo.Pattern pattern = (MediaCodec.CryptoInfo.Pattern) fp.c;
            pattern.set(i6, i7);
            ((MediaCodec.CryptoInfo) fp.b).setPattern(pattern);
            long j4 = c0186z.c;
            int i8 = (int) (j3 - j4);
            c0186z.c = j4 + i8;
            c0186z.b -= i8;
        }
        if (!mc.s(268435456)) {
            mc.w(c0186z.b);
            return g(p0Var, c0186z.c, mc.e, c0186z.b);
        }
        kn.g(4);
        androidx.compose.foundation.lazy.layout.p0 p0VarH2 = h(p0Var, c0186z.c, kn.a, 4);
        int iC = kn.C();
        c0186z.c += 4;
        c0186z.b -= 4;
        mc.w(iC);
        androidx.compose.foundation.lazy.layout.p0 p0VarG = g(p0VarH2, c0186z.c, mc.e, iC);
        c0186z.c += iC;
        int i9 = c0186z.b - iC;
        c0186z.b = i9;
        ByteBuffer byteBuffer = mc.h;
        if (byteBuffer == null || byteBuffer.capacity() < i9) {
            mc.h = ByteBuffer.allocate(i9);
        } else {
            mc.h.clear();
        }
        return g(p0VarG, c0186z.c, mc.h, c0186z.b);
    }

    public void a(DBTerm dBTerm, Uri uri) {
        if (dBTerm != null) {
            DBImage dBImage = new DBImage();
            dBImage.setLocalPath(uri.toString());
            com.quizlet.infra.legacysyncengine.managers.i iVar = (com.quizlet.infra.legacysyncengine.managers.i) this.b;
            iVar.c(dBImage);
            dBTerm.setDefinitionImageId(Long.valueOf(dBImage.getId()));
            dBTerm.setDefinitionImage(dBImage);
            iVar.c(dBTerm);
        }
    }

    public void b(DBTerm dBTerm, Uri uri) {
        try {
            try {
                Intrinsics.checkNotNullParameter(uri, "uri");
                String path = uri.getPath();
                if (path == null) {
                    throw new NullPointerException("URI path cannot be null");
                }
                File file = new File(path);
                Set set = com.quizlet.qutils.image.capture.c.a;
                Intrinsics.checkNotNullParameter(file, "<this>");
                if (!kotlin.text.D.l(kotlin.io.k.f(file), "GIF", true)) {
                    c(file);
                }
                a(dBTerm, uri);
                ((EditSetFragment) this.d).d0(dBTerm);
                this.f = null;
                this.a = 0L;
            } catch (IOException e) {
                timber.log.c.a(e);
                this.f = null;
                this.a = 0L;
            }
        } catch (Throwable th) {
            this.f = null;
            this.a = 0L;
            throw th;
        }
    }

    public void d(Fragment fragment) {
        Context contextRequireContext = fragment.requireContext();
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) this.c;
        if (!contextRequireContext.getPackageManager().hasSystemFeature("android.hardware.camera.any")) {
            timber.log.c.b(new RuntimeException("User does not have a camera"));
            return;
        }
        if (androidx.core.content.c.a(fragment.requireContext(), "android.permission.CAMERA") == 0) {
            aVar.F(fragment, false);
            return;
        }
        EditSetFragment editSetFragment = (EditSetFragment) this.d;
        androidx.camera.camera2.internal.compat.workaround.e eVar = editSetFragment.q;
        if (eVar != null) {
            eVar.p(editSetFragment);
        } else {
            Intrinsics.m("permissionsManager");
            throw null;
        }
    }

    public void e(long j) {
        androidx.compose.foundation.lazy.layout.p0 p0Var;
        if (j != -1) {
            while (true) {
                p0Var = (androidx.compose.foundation.lazy.layout.p0) this.c;
                if (j < p0Var.b) {
                    break;
                }
                C1963dG c1963dG = (C1963dG) this.f;
                ZF zf = (ZF) p0Var.c;
                synchronized (c1963dG) {
                    ZF[] zfArr = c1963dG.d;
                    int i = c1963dG.c;
                    c1963dG.c = i + 1;
                    zfArr[i] = zf;
                    c1963dG.b--;
                    c1963dG.notifyAll();
                }
                androidx.compose.foundation.lazy.layout.p0 p0Var2 = (androidx.compose.foundation.lazy.layout.p0) this.c;
                p0Var2.c = null;
                androidx.compose.foundation.lazy.layout.p0 p0Var3 = (androidx.compose.foundation.lazy.layout.p0) p0Var2.d;
                p0Var2.d = null;
                this.c = p0Var3;
            }
            if (((androidx.compose.foundation.lazy.layout.p0) this.d).a < p0Var.a) {
                this.d = p0Var;
            }
        }
    }

    public int f(int i) {
        ZF zf;
        androidx.compose.foundation.lazy.layout.p0 p0Var = (androidx.compose.foundation.lazy.layout.p0) this.e;
        if (((ZF) p0Var.c) == null) {
            C1963dG c1963dG = (C1963dG) this.f;
            synchronized (c1963dG) {
                try {
                    int i2 = c1963dG.b + 1;
                    c1963dG.b = i2;
                    int i3 = c1963dG.c;
                    if (i3 > 0) {
                        ZF[] zfArr = c1963dG.d;
                        int i4 = i3 - 1;
                        c1963dG.c = i4;
                        zf = zfArr[i4];
                        if (zf == null) {
                            throw null;
                        }
                        zfArr[i4] = null;
                    } else {
                        zf = new ZF(new byte[65536]);
                        ZF[] zfArr2 = c1963dG.d;
                        int length = zfArr2.length;
                        if (i2 > length) {
                            c1963dG.d = (ZF[]) Arrays.copyOf(zfArr2, length + length);
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            androidx.compose.foundation.lazy.layout.p0 p0Var2 = new androidx.compose.foundation.lazy.layout.p0(((androidx.compose.foundation.lazy.layout.p0) this.e).b);
            p0Var.c = zf;
            p0Var.d = p0Var2;
        }
        return Math.min(i, (int) (((androidx.compose.foundation.lazy.layout.p0) this.e).b - this.a));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I7
    public C0122z zza() {
        int iLimit;
        com.google.mlkit.vision.barcode.internal.e eVar = (com.google.mlkit.vision.barcode.internal.e) this.b;
        long j = this.a;
        EnumC3290w5 enumC3290w5 = (EnumC3290w5) this.c;
        C3268u c3268u = (C3268u) this.d;
        C3268u c3268u2 = (C3268u) this.e;
        com.google.mlkit.vision.common.a aVar = (com.google.mlkit.vision.common.a) this.f;
        eVar.getClass();
        C1608n c1608n = new C1608n();
        com.quizlet.remote.model.notes.e eVar2 = new com.quizlet.remote.model.notes.e(7);
        eVar2.b = Long.valueOf(j & Long.MAX_VALUE);
        eVar2.c = enumC3290w5;
        eVar2.d = Boolean.valueOf(com.google.mlkit.vision.barcode.internal.e.j);
        Boolean bool = Boolean.TRUE;
        eVar2.e = bool;
        eVar2.f = bool;
        c1608n.a = new C3196l5(eVar2);
        c1608n.b = com.google.mlkit.vision.barcode.internal.a.a(eVar.d);
        c1608n.c = c3268u.h();
        c1608n.d = c3268u2.h();
        int i = aVar.f;
        if (i == -1) {
            Bitmap bitmap = aVar.a;
            com.google.android.gms.common.internal.u.h(bitmap);
            iLimit = bitmap.getAllocationByteCount();
        } else {
            if (i == 17 || i == 842094169) {
                com.google.android.gms.common.internal.u.h(null);
                throw null;
            }
            if (i != 35) {
                iLimit = 0;
            } else {
                Image.Plane[] planeArrA = aVar.a();
                com.google.android.gms.common.internal.u.h(planeArrA);
                iLimit = (planeArrA[0].getBuffer().limit() * 3) / 2;
            }
        }
        androidx.work.impl.model.v vVar = new androidx.work.impl.model.v(10, false);
        vVar.b = i != -1 ? i != 35 ? i != 842094169 ? i != 16 ? i != 17 ? EnumC3151g5.UNKNOWN_FORMAT : EnumC3151g5.NV21 : EnumC3151g5.NV16 : EnumC3151g5.YV12 : EnumC3151g5.YUV_420_888 : EnumC3151g5.BITMAP;
        vVar.c = Integer.valueOf(Integer.MAX_VALUE & iLimit);
        c1608n.e = new C3160h5(vVar);
        androidx.camera.camera2.internal.c0 c0Var = new androidx.camera.camera2.internal.c0(9, false);
        c0Var.d = eVar.i ? EnumC3282v5.TYPE_THICK : EnumC3282v5.TYPE_THIN;
        c0Var.e = new com.google.android.gms.internal.mlkit_vision_barcode.I5(c1608n);
        return new C0122z(c0Var, 0);
    }
}
