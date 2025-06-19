package androidx.core.app;

import android.app.Notification;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Shader;
import android.os.Build;
import androidx.core.graphics.drawable.IconCompat;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.core.app.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1031s extends F {
    public IconCompat a;
    public IconCompat b;
    public boolean c;

    public final void a(CharSequence charSequence) {
        this.mBigContentTitle = C1034v.b(charSequence);
    }

    @Override // androidx.core.app.F
    public final void apply(InterfaceC1024k interfaceC1024k) {
        Bitmap bitmap;
        Notification.BigPictureStyle bigContentTitle = new Notification.BigPictureStyle(((H) interfaceC1024k).b).setBigContentTitle(this.mBigContentTitle);
        IconCompat iconCompat = this.a;
        if (iconCompat != null) {
            if (Build.VERSION.SDK_INT >= 31) {
                r.a(bigContentTitle, iconCompat.e(interfaceC1024k instanceof H ? ((H) interfaceC1024k).a : null));
            } else if (iconCompat.c() == 1) {
                IconCompat iconCompat2 = this.a;
                int i = iconCompat2.a;
                if (i == -1) {
                    Object obj = iconCompat2.b;
                    bitmap = obj instanceof Bitmap ? (Bitmap) obj : null;
                } else if (i == 1) {
                    bitmap = (Bitmap) iconCompat2.b;
                } else {
                    if (i != 5) {
                        throw new IllegalStateException("called getBitmap() on " + iconCompat2);
                    }
                    Bitmap bitmap2 = (Bitmap) iconCompat2.b;
                    int iMin = (int) (Math.min(bitmap2.getWidth(), bitmap2.getHeight()) * 0.6666667f);
                    Bitmap bitmapCreateBitmap = Bitmap.createBitmap(iMin, iMin, Bitmap.Config.ARGB_8888);
                    Canvas canvas = new Canvas(bitmapCreateBitmap);
                    Paint paint = new Paint(3);
                    float f = iMin;
                    float f2 = 0.5f * f;
                    float f3 = 0.9166667f * f2;
                    float f4 = 0.010416667f * f;
                    paint.setColor(0);
                    paint.setShadowLayer(f4, DefinitionKt.NO_Float_VALUE, f * 0.020833334f, 1023410176);
                    canvas.drawCircle(f2, f2, f3, paint);
                    paint.setShadowLayer(f4, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 503316480);
                    canvas.drawCircle(f2, f2, f3, paint);
                    paint.clearShadowLayer();
                    paint.setColor(-16777216);
                    Shader.TileMode tileMode = Shader.TileMode.CLAMP;
                    BitmapShader bitmapShader = new BitmapShader(bitmap2, tileMode, tileMode);
                    Matrix matrix = new Matrix();
                    matrix.setTranslate((-(bitmap2.getWidth() - iMin)) / 2.0f, (-(bitmap2.getHeight() - iMin)) / 2.0f);
                    bitmapShader.setLocalMatrix(matrix);
                    paint.setShader(bitmapShader);
                    canvas.drawCircle(f2, f2, f3, paint);
                    canvas.setBitmap(null);
                    bitmap = bitmapCreateBitmap;
                }
                bigContentTitle = bigContentTitle.bigPicture(bitmap);
            }
        }
        if (this.c) {
            IconCompat iconCompat3 = this.b;
            if (iconCompat3 == null) {
                bigContentTitle.bigLargeIcon((Bitmap) null);
            } else {
                AbstractC1030q.a(bigContentTitle, iconCompat3.e(interfaceC1024k instanceof H ? ((H) interfaceC1024k).a : null));
            }
        }
        if (this.mSummaryTextSet) {
            bigContentTitle.setSummaryText(this.mSummaryText);
        }
        if (Build.VERSION.SDK_INT >= 31) {
            r.c(bigContentTitle, false);
            r.b(bigContentTitle, null);
        }
    }

    public final void b(CharSequence charSequence) {
        this.mSummaryText = C1034v.b(charSequence);
        this.mSummaryTextSet = true;
    }

    @Override // androidx.core.app.F
    public final String getClassName() {
        return "androidx.core.app.NotificationCompat$BigPictureStyle";
    }
}
