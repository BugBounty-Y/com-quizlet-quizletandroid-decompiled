package androidx.compose.material3;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import androidx.compose.material3.internal.C0658w;
import androidx.compose.ui.text.C0995g;
import com.lyft.android.scissors.CropView;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import kotlin.text.StringsKt;

/* renamed from: androidx.compose.material3.b1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0591b1 implements androidx.compose.ui.text.input.K {
    public int a;
    public int b;
    public int c;
    public final Object d;
    public Object e;

    public C0591b1(int i, int i2, int i3) {
        String str;
        if (i != Integer.MIN_VALUE) {
            str = i + "/";
        } else {
            str = "";
        }
        this.d = str;
        this.a = i2;
        this.b = i3;
        this.c = Integer.MIN_VALUE;
        this.e = "";
    }

    public Future a(File file) {
        Bitmap bitmapCreateScaledBitmap;
        int i = this.b;
        int i2 = this.c;
        CropView cropView = (CropView) this.d;
        Bitmap bitmap = cropView.e;
        if (bitmap == null) {
            bitmapCreateScaledBitmap = null;
        } else {
            Bitmap.Config config = bitmap.getConfig();
            if (config == null) {
                config = Bitmap.Config.ARGB_8888;
            }
            com.lyft.android.scissors.k kVar = cropView.a;
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(kVar.h, kVar.i, config);
            Canvas canvas = new Canvas(bitmapCreateBitmap);
            canvas.translate(-((cropView.getRight() - r6) / 2), -((cropView.getBottom() - r5) / 2));
            cropView.a(canvas);
            ExecutorService executorService = com.lyft.android.scissors.n.a;
            int i3 = 1;
            if (i > 0) {
                while (bitmapCreateBitmap.getWidth() / i3 > i) {
                    i3 *= 2;
                }
            }
            if (i2 > 0) {
                while (bitmapCreateBitmap.getHeight() / i3 > i2) {
                    i3 *= 2;
                }
            }
            bitmapCreateScaledBitmap = Bitmap.createScaledBitmap(bitmapCreateBitmap, bitmapCreateBitmap.getWidth() / i3, bitmapCreateBitmap.getHeight() / i3, false);
        }
        return com.lyft.android.scissors.n.a.submit(new com.google.android.gms.measurement.internal.G0(file, bitmapCreateScaledBitmap, (Bitmap.CompressFormat) this.e, this.a), null);
    }

    public void b() {
        int i = this.c;
        int i2 = i == Integer.MIN_VALUE ? this.a : i + this.b;
        this.c = i2;
        this.e = ((String) this.d) + i2;
    }

    public void c() {
        if (this.c == Integer.MIN_VALUE) {
            throw new IllegalStateException("generateNewId() must be called before retrieving ids.");
        }
    }

    @Override // androidx.compose.ui.text.input.K
    public androidx.compose.ui.text.input.I e(C0995g c0995g) {
        int length = c0995g.a.length();
        int i = 0;
        String strZ = c0995g.a;
        int i2 = this.c;
        if (length > i2) {
            strZ = StringsKt.Z(strZ, kotlin.ranges.l.h(0, i2));
        }
        String string = "";
        int i3 = 0;
        while (i < strZ.length()) {
            int i4 = i3 + 1;
            string = string + strZ.charAt(i);
            if (i4 == this.a || i3 + 2 == this.b) {
                StringBuilder sbU = androidx.compose.animation.d0.u(string);
                sbU.append(((C0658w) this.d).b);
                string = sbU.toString();
            }
            i++;
            i3 = i4;
        }
        return new androidx.compose.ui.text.input.I(new C0995g(6, string, null), (androidx.webkit.internal.p) this.e);
    }

    public C0591b1(CropView cropView) {
        this.e = Bitmap.CompressFormat.JPEG;
        this.a = 100;
        this.b = 0;
        this.c = 0;
        ExecutorService executorService = com.lyft.android.scissors.n.a;
        if (cropView == null) {
            throw new NullPointerException("cropView == null");
        }
        this.d = cropView;
    }

    public C0591b1(C0658w c0658w) {
        this.d = c0658w;
        String str = c0658w.a;
        char c = c0658w.b;
        this.a = StringsKt.L(str, c, 0, false, 6);
        this.b = StringsKt.P(str, c, 0, 6);
        this.c = c0658w.c.length();
        this.e = new androidx.webkit.internal.p(this, 5);
    }
}
