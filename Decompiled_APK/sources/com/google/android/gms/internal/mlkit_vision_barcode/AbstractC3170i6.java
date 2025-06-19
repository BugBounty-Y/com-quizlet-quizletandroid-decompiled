package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.res.Resources;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.StrictMode;
import android.util.Log;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0696o3;
import androidx.compose.material3.C0702p3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.compose.C4832z;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.i6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3170i6 {
    /* JADX WARN: Removed duplicated region for block: B:45:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:67:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final boolean r17, final boolean r18, final long r19, final kotlin.jvm.functions.Function0 r21, androidx.compose.ui.q r22, final androidx.compose.runtime.internal.d r23, androidx.compose.runtime.InterfaceC0806l r24, final int r25, final int r26) {
        /*
            Method dump skipped, instructions count: 282
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6.a(boolean, boolean, long, kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x017a  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0192  */
    /* JADX WARN: Removed duplicated region for block: B:69:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final java.lang.String r23, final androidx.compose.ui.graphics.painter.b r24, final java.lang.String r25, final androidx.compose.ui.q r26, final long r27, float r29, final long r30, androidx.compose.runtime.InterfaceC0806l r32, final int r33, final int r34) {
        /*
            Method dump skipped, instructions count: 414
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6.b(java.lang.String, androidx.compose.ui.graphics.painter.b, java.lang.String, androidx.compose.ui.q, long, float, long, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(final boolean z, final boolean z2, final String label, final androidx.compose.ui.graphics.painter.b leadingIcon, final String str, final androidx.compose.ui.graphics.painter.b bVar, final String str2, final Function0 onContentClick, final androidx.compose.ui.q qVar, final long j, final float f, final long j2, final long j3, Function0 function0, InterfaceC0806l interfaceC0806l, final int i) {
        Function0 function02;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(leadingIcon, "leadingIcon");
        Intrinsics.checkNotNullParameter(onContentClick, "onContentClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-486252448);
        int i2 = i | (c0814p2.g(z) ? 4 : 2) | (c0814p2.g(z2) ? 32 : 16) | (c0814p2.f(label) ? 256 : 128) | (c0814p2.h(leadingIcon) ? 2048 : 1024) | (c0814p2.f(str) ? 16384 : 8192) | (c0814p2.h(bVar) ? 131072 : 65536) | (c0814p2.f(str2) ? 1048576 : 524288) | (c0814p2.h(onContentClick) ? 8388608 : 4194304) | (c0814p2.f(qVar) ? 67108864 : 33554432) | (c0814p2.e(j) ? 536870912 : 268435456);
        int i3 = (c0814p2.c(f) ? 4 : 2) | (c0814p2.e(j2) ? 32 : 16) | (c0814p2.e(j3) ? 256 : 128) | (c0814p2.h(function0) ? 2048 : 1024);
        if ((i2 & 306783379) == 306783378 && (i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            function02 = function0;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p2, 54);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            function02 = function0;
            a(z, z2, C0861v.f, onContentClick, null, androidx.compose.runtime.internal.e.e(270525674, new com.quizlet.features.infra.folder.menu.composable.foldersubfolder.h(label, leadingIcon, str, j, f, j2), c0814p2), c0814p2, (i2 & 14) | 196992 | (i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 12) & 7168), 16);
            c0814p = c0814p2;
            c0814p.X(-1624454597);
            if (bVar != null) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.h();
                androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.g);
                C0702p3 c0702p3B = AbstractC0696o3.b(false);
                c0814p.X(-1624444813);
                boolean z3 = (i3 & 7168) == 2048;
                Object objI = c0814p.I();
                if (z3 || objI == C0804k.a) {
                    objI = new com.braze.support.u(16, function02);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                androidx.compose.material3.D1.a(bVar, str2, AbstractC0460p.k(qVarK, null, c0702p3B, false, null, (Function0) objI, 28), j3, c0814p, ((i2 >> 15) & 126) | ((i3 << 3) & 7168), 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            final Function0 function03 = function02;
            c0813o0R.d = new Function2(z, z2, label, leadingIcon, str, bVar, str2, onContentClick, qVar, j, f, j2, j3, function03, i) { // from class: com.quizlet.features.infra.folder.menu.composable.foldersubfolder.g
                public final /* synthetic */ boolean a;
                public final /* synthetic */ boolean b;
                public final /* synthetic */ String c;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b d;
                public final /* synthetic */ String e;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b f;
                public final /* synthetic */ String g;
                public final /* synthetic */ Function0 h;
                public final /* synthetic */ q i;
                public final /* synthetic */ long j;
                public final /* synthetic */ float k;
                public final /* synthetic */ long l;
                public final /* synthetic */ long m;
                public final /* synthetic */ Function0 n;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    long j4 = this.m;
                    Function0 function04 = this.n;
                    AbstractC3170i6.c(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, j4, function04, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static void d(Closeable closeable) throws IOException {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException unused) {
            }
        }
    }

    public static boolean e(File file, Resources resources, int i) throws Throwable {
        InputStream inputStreamOpenRawResource;
        try {
            inputStreamOpenRawResource = resources.openRawResource(i);
            try {
                boolean zF = f(file, inputStreamOpenRawResource);
                d(inputStreamOpenRawResource);
                return zF;
            } catch (Throwable th) {
                th = th;
                d(inputStreamOpenRawResource);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            inputStreamOpenRawResource = null;
        }
    }

    public static boolean f(File file, InputStream inputStream) throws Throwable {
        FileOutputStream fileOutputStream;
        StrictMode.ThreadPolicy threadPolicyAllowThreadDiskWrites = StrictMode.allowThreadDiskWrites();
        FileOutputStream fileOutputStream2 = null;
        try {
            try {
                fileOutputStream = new FileOutputStream(file, false);
            } catch (IOException e) {
                e = e;
            }
        } catch (Throwable th) {
            th = th;
        }
        try {
            byte[] bArr = new byte[1024];
            while (true) {
                int i = inputStream.read(bArr);
                if (i == -1) {
                    d(fileOutputStream);
                    StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskWrites);
                    return true;
                }
                fileOutputStream.write(bArr, 0, i);
            }
        } catch (IOException e2) {
            e = e2;
            fileOutputStream2 = fileOutputStream;
            Log.e("TypefaceCompatUtil", "Error copying resource contents to temp file: " + e.getMessage());
            d(fileOutputStream2);
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskWrites);
            return false;
        } catch (Throwable th2) {
            th = th2;
            fileOutputStream2 = fileOutputStream;
            d(fileOutputStream2);
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskWrites);
            throw th;
        }
    }

    public static final C4832z g(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1864813772);
        float f = com.quizlet.assembly.compose.tags.g.a;
        C4832z c4832zA = com.quizlet.assembly.compose.tags.g.a(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, 0L, 0L, 0L, c0814p, 509);
        c0814p.p(false);
        return c4832zA;
    }

    public static File h(Context context) {
        File cacheDir = context.getCacheDir();
        if (cacheDir == null) {
            return null;
        }
        String str = ".font" + Process.myPid() + "-" + Process.myTid() + "-";
        for (int i = 0; i < 100; i++) {
            File file = new File(cacheDir, str + i);
            if (file.createNewFile()) {
                return file;
            }
        }
        return null;
    }

    public static final boolean i(Context context) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        return context.getResources().getBoolean(R.bool.isLargeDevice);
    }

    public static MappedByteBuffer j(Context context, Uri uri) throws IOException {
        ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor;
        try {
            parcelFileDescriptorOpenFileDescriptor = context.getContentResolver().openFileDescriptor(uri, "r", null);
        } catch (IOException unused) {
        }
        if (parcelFileDescriptorOpenFileDescriptor == null) {
            if (parcelFileDescriptorOpenFileDescriptor != null) {
                parcelFileDescriptorOpenFileDescriptor.close();
                return null;
            }
            return null;
        }
        try {
            FileInputStream fileInputStream = new FileInputStream(parcelFileDescriptorOpenFileDescriptor.getFileDescriptor());
            try {
                FileChannel channel = fileInputStream.getChannel();
                MappedByteBuffer map = channel.map(FileChannel.MapMode.READ_ONLY, 0L, channel.size());
                fileInputStream.close();
                parcelFileDescriptorOpenFileDescriptor.close();
                return map;
            } finally {
            }
        } finally {
        }
    }

    public static androidx.compose.foundation.layout.A0 k() {
        com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
        mVar.s();
        float f = com.quizlet.ui.resources.designsystem.generated.j.h;
        mVar.s();
        return new androidx.compose.foundation.layout.A0(f, f, f, f);
    }
}
