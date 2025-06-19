package androidx.appcompat.widget;

import android.R;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Shader;
import android.graphics.drawable.AnimationDrawable;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ClipDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.RoundRectShape;
import android.text.method.KeyListener;
import android.text.method.NumberKeyListener;
import android.util.AttributeSet;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.AbsSeekBar;
import android.widget.EditText;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.pubmatic.sdk.video.c;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* loaded from: classes.dex */
public class C {
    public static final int[] d = {R.attr.indeterminateDrawable, R.attr.progressDrawable};
    public final /* synthetic */ int a = 0;
    public final View b;
    public Object c;

    public C(AbsSeekBar absSeekBar) {
        this.b = absSeekBar;
    }

    public KeyListener a(KeyListener keyListener) {
        if (keyListener instanceof NumberKeyListener) {
            return keyListener;
        }
        ((androidx.work.impl.model.v) ((androidx.appcompat.app.Q) this.c).a).getClass();
        if (keyListener instanceof androidx.emoji2.viewsintegration.d) {
            return keyListener;
        }
        if (keyListener == null) {
            return null;
        }
        return keyListener instanceof NumberKeyListener ? keyListener : new androidx.emoji2.viewsintegration.d(keyListener);
    }

    public void b(AttributeSet attributeSet, int i) {
        switch (this.a) {
            case 0:
                AbsSeekBar absSeekBar = (AbsSeekBar) this.b;
                com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(absSeekBar.getContext(), attributeSet, d, i);
                Drawable drawableH = eVarM.h(0);
                if (drawableH != null) {
                    if (drawableH instanceof AnimationDrawable) {
                        AnimationDrawable animationDrawable = (AnimationDrawable) drawableH;
                        int numberOfFrames = animationDrawable.getNumberOfFrames();
                        AnimationDrawable animationDrawable2 = new AnimationDrawable();
                        animationDrawable2.setOneShot(animationDrawable.isOneShot());
                        for (int i2 = 0; i2 < numberOfFrames; i2++) {
                            Drawable drawableE = e(animationDrawable.getFrame(i2), true);
                            drawableE.setLevel(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            animationDrawable2.addFrame(drawableE, animationDrawable.getDuration(i2));
                        }
                        animationDrawable2.setLevel(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                        drawableH = animationDrawable2;
                    }
                    absSeekBar.setIndeterminateDrawable(drawableH);
                }
                Drawable drawableH2 = eVarM.h(1);
                if (drawableH2 != null) {
                    absSeekBar.setProgressDrawable(e(drawableH2, false));
                }
                eVarM.n();
                return;
            default:
                TypedArray typedArrayObtainStyledAttributes = ((EditText) this.b).getContext().obtainStyledAttributes(attributeSet, androidx.appcompat.a.i, i, 0);
                try {
                    boolean z = typedArrayObtainStyledAttributes.hasValue(14) ? typedArrayObtainStyledAttributes.getBoolean(14, true) : true;
                    typedArrayObtainStyledAttributes.recycle();
                    d(z);
                    return;
                } catch (Throwable th) {
                    typedArrayObtainStyledAttributes.recycle();
                    throw th;
                }
        }
    }

    public androidx.emoji2.viewsintegration.b c(InputConnection inputConnection, EditorInfo editorInfo) {
        androidx.appcompat.app.Q q = (androidx.appcompat.app.Q) this.c;
        if (inputConnection == null) {
            q.getClass();
            inputConnection = null;
        } else {
            androidx.work.impl.model.v vVar = (androidx.work.impl.model.v) q.a;
            vVar.getClass();
            if (!(inputConnection instanceof androidx.emoji2.viewsintegration.b)) {
                inputConnection = new androidx.emoji2.viewsintegration.b((EditText) vVar.b, inputConnection, editorInfo);
            }
        }
        return (androidx.emoji2.viewsintegration.b) inputConnection;
    }

    public void d(boolean z) {
        androidx.emoji2.viewsintegration.g gVar = (androidx.emoji2.viewsintegration.g) ((androidx.work.impl.model.v) ((androidx.appcompat.app.Q) this.c).a).c;
        if (gVar.c != z) {
            if (gVar.b != null) {
                androidx.emoji2.text.j jVarA = androidx.emoji2.text.j.a();
                l1 l1Var = gVar.b;
                jVarA.getClass();
                AbstractC3242q6.g(l1Var, "initCallback cannot be null");
                ReentrantReadWriteLock reentrantReadWriteLock = jVarA.a;
                reentrantReadWriteLock.writeLock().lock();
                try {
                    jVarA.b.remove(l1Var);
                } finally {
                    reentrantReadWriteLock.writeLock().unlock();
                }
            }
            gVar.c = z;
            if (z) {
                androidx.emoji2.viewsintegration.g.a(gVar.a, androidx.emoji2.text.j.a().b());
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public Drawable e(Drawable drawable, boolean z) {
        if (drawable instanceof androidx.core.graphics.drawable.a) {
            ((androidx.core.graphics.drawable.b) ((androidx.core.graphics.drawable.a) drawable)).getClass();
        } else {
            if (drawable instanceof LayerDrawable) {
                LayerDrawable layerDrawable = (LayerDrawable) drawable;
                int numberOfLayers = layerDrawable.getNumberOfLayers();
                Drawable[] drawableArr = new Drawable[numberOfLayers];
                for (int i = 0; i < numberOfLayers; i++) {
                    int id = layerDrawable.getId(i);
                    drawableArr[i] = e(layerDrawable.getDrawable(i), id == 16908301 || id == 16908303);
                }
                LayerDrawable layerDrawable2 = new LayerDrawable(drawableArr);
                for (int i2 = 0; i2 < numberOfLayers; i2++) {
                    layerDrawable2.setId(i2, layerDrawable.getId(i2));
                    layerDrawable2.setLayerGravity(i2, layerDrawable.getLayerGravity(i2));
                    layerDrawable2.setLayerWidth(i2, layerDrawable.getLayerWidth(i2));
                    layerDrawable2.setLayerHeight(i2, layerDrawable.getLayerHeight(i2));
                    layerDrawable2.setLayerInsetLeft(i2, layerDrawable.getLayerInsetLeft(i2));
                    layerDrawable2.setLayerInsetRight(i2, layerDrawable.getLayerInsetRight(i2));
                    layerDrawable2.setLayerInsetTop(i2, layerDrawable.getLayerInsetTop(i2));
                    layerDrawable2.setLayerInsetBottom(i2, layerDrawable.getLayerInsetBottom(i2));
                    layerDrawable2.setLayerInsetStart(i2, layerDrawable.getLayerInsetStart(i2));
                    layerDrawable2.setLayerInsetEnd(i2, layerDrawable.getLayerInsetEnd(i2));
                }
                return layerDrawable2;
            }
            if (drawable instanceof BitmapDrawable) {
                BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                Bitmap bitmap = bitmapDrawable.getBitmap();
                if (((Bitmap) this.c) == null) {
                    this.c = bitmap;
                }
                ShapeDrawable shapeDrawable = new ShapeDrawable(new RoundRectShape(new float[]{5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f}, null, null));
                shapeDrawable.getPaint().setShader(new BitmapShader(bitmap, Shader.TileMode.REPEAT, Shader.TileMode.CLAMP));
                shapeDrawable.getPaint().setColorFilter(bitmapDrawable.getPaint().getColorFilter());
                return z ? new ClipDrawable(shapeDrawable, 3, 1) : shapeDrawable;
            }
        }
        return drawable;
    }

    public C(EditText editText) {
        this.b = editText;
        androidx.appcompat.app.Q q = new androidx.appcompat.app.Q();
        q.a = new androidx.work.impl.model.v(editText);
        this.c = q;
    }
}
