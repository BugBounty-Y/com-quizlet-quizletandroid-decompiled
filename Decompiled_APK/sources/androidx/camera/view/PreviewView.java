package androidx.camera.view;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.util.Rational;
import android.util.Size;
import android.view.Display;
import android.view.Window;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.s0;
import androidx.camera.core.J;
import androidx.camera.core.U;
import androidx.camera.core.W;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.j0;
import androidx.camera.core.m0;
import androidx.camera.view.internal.compat.quirk.SurfaceViewNotCroppedByParentQuirk;
import androidx.camera.view.internal.compat.quirk.SurfaceViewStretchedQuirk;
import androidx.core.view.V;
import androidx.lifecycle.T;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class PreviewView extends FrameLayout {
    public static final /* synthetic */ int m = 0;
    public g a;
    public j b;
    public final n c;
    public final c d;
    public boolean e;
    public final Y f;
    public final AtomicReference g;
    public final k h;
    public InterfaceC0183w i;
    public final f j;
    public final d k;
    public final e l;

    public PreviewView(@NonNull Context context) {
        this(context, null);
    }

    public static boolean b(j0 j0Var, g gVar) {
        boolean zEquals = j0Var.d.n().f().equals("androidx.camera.camera2.legacy");
        boolean z = (androidx.camera.view.internal.compat.quirk.a.a.b(SurfaceViewStretchedQuirk.class) == null && androidx.camera.view.internal.compat.quirk.a.a.b(SurfaceViewNotCroppedByParentQuirk.class) == null) ? false : true;
        if (!zEquals && !z) {
            int iOrdinal = gVar.ordinal();
            if (iOrdinal == 0) {
                return false;
            }
            if (iOrdinal != 1) {
                throw new IllegalArgumentException("Invalid implementation mode: " + gVar);
            }
        }
        return true;
    }

    private DisplayManager getDisplayManager() {
        Context context = getContext();
        if (context == null) {
            return null;
        }
        return (DisplayManager) context.getApplicationContext().getSystemService("display");
    }

    private J getScreenFlashInternal() {
        return this.c.getScreenFlash();
    }

    private int getViewPortScaleType() {
        int iOrdinal = getScaleType().ordinal();
        if (iOrdinal == 0) {
            return 0;
        }
        int i = 1;
        if (iOrdinal != 1) {
            i = 2;
            if (iOrdinal != 2) {
                i = 3;
                if (iOrdinal != 3 && iOrdinal != 4 && iOrdinal != 5) {
                    throw new IllegalStateException("Unexpected scale type: " + getScaleType());
                }
            }
        }
        return i;
    }

    private void setScreenFlashUiInfo(J j) {
        AbstractC3053s1.f(3, "PreviewView");
    }

    public final void a() {
        Rect rect;
        Display display;
        InterfaceC0183w interfaceC0183w;
        S.d();
        if (this.b != null) {
            if (this.e && (display = getDisplay()) != null && (interfaceC0183w = this.i) != null) {
                int iG = interfaceC0183w.g(display.getRotation());
                int rotation = display.getRotation();
                c cVar = this.d;
                if (cVar.g) {
                    cVar.c = iG;
                    cVar.e = rotation;
                }
            }
            this.b.i();
        }
        k kVar = this.h;
        Size size = new Size(getWidth(), getHeight());
        int layoutDirection = getLayoutDirection();
        kVar.getClass();
        S.d();
        synchronized (kVar) {
            try {
                if (size.getWidth() != 0 && size.getHeight() != 0 && (rect = kVar.b) != null) {
                    kVar.a.a(size, layoutDirection, rect);
                }
            } finally {
            }
        }
    }

    public Bitmap getBitmap() {
        Bitmap bitmapD;
        S.d();
        j jVar = this.b;
        if (jVar == null || (bitmapD = jVar.d()) == null) {
            return null;
        }
        FrameLayout frameLayout = (FrameLayout) jVar.c;
        Size size = new Size(frameLayout.getWidth(), frameLayout.getHeight());
        int layoutDirection = frameLayout.getLayoutDirection();
        c cVar = (c) jVar.d;
        if (!cVar.f()) {
            return bitmapD;
        }
        Matrix matrixD = cVar.d();
        RectF rectFE = cVar.e(size, layoutDirection);
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(size.getWidth(), size.getHeight(), bitmapD.getConfig());
        Canvas canvas = new Canvas(bitmapCreateBitmap);
        Matrix matrix = new Matrix();
        matrix.postConcat(matrixD);
        matrix.postScale(rectFE.width() / cVar.a.getWidth(), rectFE.height() / cVar.a.getHeight());
        matrix.postTranslate(rectFE.left, rectFE.top);
        canvas.drawBitmap(bitmapD, matrix, new Paint(7));
        return bitmapCreateBitmap;
    }

    public a getController() {
        S.d();
        return null;
    }

    @NonNull
    public g getImplementationMode() {
        S.d();
        return this.a;
    }

    @NonNull
    public U getMeteringPointFactory() {
        S.d();
        return this.h;
    }

    public androidx.camera.view.transform.a getOutputTransform() {
        Matrix matrixC;
        c cVar = this.d;
        S.d();
        try {
            matrixC = cVar.c(new Size(getWidth(), getHeight()), getLayoutDirection());
        } catch (IllegalStateException unused) {
            matrixC = null;
        }
        Rect rect = cVar.b;
        if (matrixC == null || rect == null) {
            AbstractC3053s1.f(3, "PreviewView");
            return null;
        }
        RectF rectF = androidx.camera.core.impl.utils.f.a;
        RectF rectF2 = new RectF(rect);
        Matrix matrix = new Matrix();
        matrix.setRectToRect(androidx.camera.core.impl.utils.f.a, rectF2, Matrix.ScaleToFit.FILL);
        matrixC.preConcat(matrix);
        if (this.b instanceof s) {
            matrixC.postConcat(getMatrix());
        } else if (!getMatrix().isIdentity()) {
            AbstractC3053s1.h("PreviewView", "PreviewView needs to be in COMPATIBLE mode for the transform to work correctly.");
        }
        new Size(rect.width(), rect.height());
        return new androidx.camera.view.transform.a();
    }

    @NonNull
    public T getPreviewStreamState() {
        return this.f;
    }

    @NonNull
    public h getScaleType() {
        S.d();
        return this.d.h;
    }

    public J getScreenFlash() {
        return getScreenFlashInternal();
    }

    public Matrix getSensorToViewTransform() {
        S.d();
        if (getWidth() == 0 || getHeight() == 0) {
            return null;
        }
        Size size = new Size(getWidth(), getHeight());
        int layoutDirection = getLayoutDirection();
        c cVar = this.d;
        if (!cVar.f()) {
            return null;
        }
        Matrix matrix = new Matrix(cVar.d);
        matrix.postConcat(cVar.c(size, layoutDirection));
        return matrix;
    }

    @NonNull
    public W getSurfaceProvider() {
        S.d();
        return this.l;
    }

    public m0 getViewPort() {
        S.d();
        if (getDisplay() == null) {
            return null;
        }
        getDisplay().getRotation();
        S.d();
        if (getWidth() == 0 || getHeight() == 0) {
            return null;
        }
        new Rational(getWidth(), getHeight());
        getViewPortScaleType();
        getLayoutDirection();
        return new m0();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        DisplayManager displayManager = getDisplayManager();
        if (displayManager != null) {
            displayManager.registerDisplayListener(this.j, new Handler(Looper.getMainLooper()));
        }
        addOnLayoutChangeListener(this.k);
        j jVar = this.b;
        if (jVar != null) {
            jVar.f();
        }
        S.d();
        getViewPort();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeOnLayoutChangeListener(this.k);
        j jVar = this.b;
        if (jVar != null) {
            jVar.g();
        }
        DisplayManager displayManager = getDisplayManager();
        if (displayManager == null) {
            return;
        }
        displayManager.unregisterDisplayListener(this.j);
    }

    public void setController(a aVar) {
        S.d();
        S.d();
        getViewPort();
        setScreenFlashUiInfo(getScreenFlashInternal());
    }

    public void setImplementationMode(@NonNull g gVar) {
        S.d();
        this.a = gVar;
    }

    public void setScaleType(@NonNull h hVar) {
        S.d();
        this.d.h = hVar;
        a();
        S.d();
        getViewPort();
    }

    public void setScreenFlashOverlayColor(int i) {
        this.c.setBackgroundColor(i);
    }

    public void setScreenFlashWindow(Window window) {
        S.d();
        this.c.setScreenFlashWindow(window);
        setScreenFlashUiInfo(getScreenFlashInternal());
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PreviewView(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0, 0);
        this.a = g.PERFORMANCE;
        c cVar = new c();
        cVar.h = h.FILL_CENTER;
        this.d = cVar;
        this.e = true;
        this.f = new Y(i.a);
        this.g = new AtomicReference();
        this.h = new k(cVar);
        this.j = new f(this);
        this.k = new d(this, 0);
        this.l = new e(this);
        S.d();
        Resources.Theme theme = context.getTheme();
        int[] iArr = l.a;
        TypedArray typedArrayObtainStyledAttributes = theme.obtainStyledAttributes(attributeSet, iArr, 0, 0);
        V.n(this, context, iArr, attributeSet, typedArrayObtainStyledAttributes, 0);
        try {
            int integer = typedArrayObtainStyledAttributes.getInteger(1, cVar.h.a);
            for (h hVar : h.values()) {
                if (hVar.a == integer) {
                    setScaleType(hVar);
                    int integer2 = typedArrayObtainStyledAttributes.getInteger(0, 0);
                    for (g gVar : g.values()) {
                        if (gVar.a == integer2) {
                            setImplementationMode(gVar);
                            typedArrayObtainStyledAttributes.recycle();
                            new com.google.firebase.heartbeatinfo.e(context, new s0(this));
                            if (getBackground() == null) {
                                setBackgroundColor(getContext().getColor(R.color.black));
                            }
                            n nVar = new n(context);
                            this.c = nVar;
                            nVar.setLayoutParams(new LinearLayout.LayoutParams(-1, -1));
                            return;
                        }
                    }
                    throw new IllegalArgumentException("Unknown implementation mode id " + integer2);
                }
            }
            throw new IllegalArgumentException("Unknown scale type id " + integer);
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }
}
