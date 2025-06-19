package com.airbnb.lottie;

import android.animation.Animator;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.provider.Settings;
import android.view.Choreographer;
import android.view.View;
import android.widget.ImageView;
import androidx.appcompat.app.L;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class u extends Drawable implements Drawable.Callback, Animatable {
    public static final List Y = Arrays.asList("reduced motion", "reduced_motion", "reduced-motion", "reducedmotion");
    public static final ThreadPoolExecutor Z = new ThreadPoolExecutor(0, 2, 35, TimeUnit.MILLISECONDS, new LinkedBlockingQueue(), new com.airbnb.lottie.utils.d());
    public Rect A;
    public RectF B;
    public com.airbnb.lottie.animation.a C;
    public Rect D;
    public Rect E;
    public RectF F;
    public RectF G;
    public Matrix H;
    public final float[] I;
    public Matrix J;
    public boolean K;
    public EnumC1461a L;
    public final Semaphore M;
    public final androidx.compose.ui.text.input.C V;
    public float W;
    public int X;
    public h a;
    public final com.airbnb.lottie.utils.e b;
    public final boolean c;
    public boolean d;
    public boolean e;
    public final ArrayList f;
    public com.airbnb.lottie.manager.a g;
    public String h;
    public com.quizlet.data.interactor.folderwithcreator.m i;
    public Map j;
    public String k;
    public final L l;
    public boolean m;
    public boolean n;
    public com.airbnb.lottie.model.layer.c o;
    public int p;
    public boolean q;
    public boolean r;
    public boolean s;
    public boolean t;
    public boolean u;
    public D v;
    public boolean w;
    public final Matrix x;
    public Bitmap y;
    public Canvas z;

    public u() {
        com.airbnb.lottie.utils.e eVar = new com.airbnb.lottie.utils.e();
        this.b = eVar;
        this.c = true;
        this.d = false;
        this.e = false;
        this.X = 1;
        this.f = new ArrayList();
        this.l = new L();
        this.m = false;
        this.n = true;
        this.p = 255;
        this.u = false;
        this.v = D.a;
        this.w = false;
        this.x = new Matrix();
        this.I = new float[9];
        this.K = false;
        s sVar = new s(this, 0);
        this.M = new Semaphore(1);
        this.V = new androidx.compose.ui.text.input.C(this, 11);
        this.W = -3.4028235E38f;
        eVar.addUpdateListener(sVar);
    }

    public static void f(Rect rect, RectF rectF) {
        rect.set((int) Math.floor(rectF.left), (int) Math.floor(rectF.top), (int) Math.ceil(rectF.right), (int) Math.ceil(rectF.bottom));
    }

    public final void a(final com.airbnb.lottie.model.e eVar, final ColorFilter colorFilter, final com.quizlet.data.repository.widget.b bVar) {
        com.airbnb.lottie.model.layer.c cVar = this.o;
        if (cVar == null) {
            this.f.add(new t() { // from class: com.airbnb.lottie.o
                @Override // com.airbnb.lottie.t
                public final void run() {
                    this.a.a(eVar, colorFilter, bVar);
                }
            });
            return;
        }
        boolean zIsEmpty = true;
        if (eVar == com.airbnb.lottie.model.e.c) {
            cVar.d(colorFilter, bVar);
        } else {
            com.airbnb.lottie.model.f fVar = eVar.b;
            if (fVar != null) {
                fVar.d(colorFilter, bVar);
            } else {
                ArrayList arrayList = new ArrayList();
                this.o.e(eVar, 0, arrayList, new com.airbnb.lottie.model.e(new String[0]));
                for (int i = 0; i < arrayList.size(); i++) {
                    ((com.airbnb.lottie.model.e) arrayList.get(i)).b.d(colorFilter, bVar);
                }
                zIsEmpty = true ^ arrayList.isEmpty();
            }
        }
        if (zIsEmpty) {
            invalidateSelf();
            if (colorFilter == y.z) {
                u(this.b.b());
            }
        }
    }

    public final boolean b(Context context) {
        if (this.d) {
            return true;
        }
        if (!this.c) {
            return false;
        }
        if (context == null) {
            return true;
        }
        Matrix matrix = com.airbnb.lottie.utils.i.a;
        return Settings.Global.getFloat(context.getContentResolver(), "animator_duration_scale", 1.0f) != DefinitionKt.NO_Float_VALUE;
    }

    public final void c() {
        h hVar = this.a;
        if (hVar == null) {
            return;
        }
        com.airbnb.lottie.parser.moshi.c cVar = com.airbnb.lottie.parser.r.a;
        Rect rect = hVar.k;
        List list = Collections.EMPTY_LIST;
        com.airbnb.lottie.model.layer.c cVar2 = new com.airbnb.lottie.model.layer.c(this, new com.airbnb.lottie.model.layer.e(list, hVar, "__container", -1L, 1, -1L, null, list, new com.airbnb.lottie.model.animatable.e(), 0, 0, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, rect.width(), rect.height(), null, null, list, 1, null, false, null, null, 1), hVar.j, hVar);
        this.o = cVar2;
        if (this.r) {
            cVar2.q(true);
        }
        this.o.L = this.n;
    }

    public final void d() {
        com.airbnb.lottie.utils.e eVar = this.b;
        if (eVar.m) {
            eVar.cancel();
            if (!isVisible()) {
                this.X = 1;
            }
        }
        this.a = null;
        this.o = null;
        this.g = null;
        this.W = -3.4028235E38f;
        eVar.l = null;
        eVar.j = -2.1474836E9f;
        eVar.k = 2.1474836E9f;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        com.airbnb.lottie.model.layer.c cVar = this.o;
        if (cVar == null) {
            return;
        }
        EnumC1461a enumC1461a = this.L;
        if (enumC1461a == null) {
            enumC1461a = EnumC1461a.a;
        }
        boolean z = enumC1461a == EnumC1461a.b;
        ThreadPoolExecutor threadPoolExecutor = Z;
        Semaphore semaphore = this.M;
        androidx.compose.ui.text.input.C c = this.V;
        com.airbnb.lottie.utils.e eVar = this.b;
        if (z) {
            try {
                semaphore.acquire();
            } catch (InterruptedException unused) {
                if (!z) {
                    return;
                }
                semaphore.release();
                if (cVar.K == eVar.b()) {
                    return;
                }
            } catch (Throwable th) {
                if (z) {
                    semaphore.release();
                    if (cVar.K != eVar.b()) {
                        threadPoolExecutor.execute(c);
                    }
                }
                throw th;
            }
        }
        if (z && v()) {
            u(eVar.b());
        }
        if (this.e) {
            try {
                if (this.w) {
                    l(canvas, cVar);
                } else {
                    g(canvas);
                }
            } catch (Throwable unused2) {
                com.airbnb.lottie.utils.c.a.getClass();
            }
        } else if (this.w) {
            l(canvas, cVar);
        } else {
            g(canvas);
        }
        this.K = false;
        if (z) {
            semaphore.release();
            if (cVar.K == eVar.b()) {
                return;
            }
            threadPoolExecutor.execute(c);
        }
    }

    public final void e() {
        h hVar = this.a;
        if (hVar == null) {
            return;
        }
        D d = this.v;
        int i = Build.VERSION.SDK_INT;
        boolean z = hVar.o;
        int i2 = hVar.p;
        int iOrdinal = d.ordinal();
        boolean z2 = false;
        if (iOrdinal != 1 && (iOrdinal == 2 || ((z && i < 28) || i2 > 4))) {
            z2 = true;
        }
        this.w = z2;
    }

    public final void g(Canvas canvas) {
        com.airbnb.lottie.model.layer.c cVar = this.o;
        h hVar = this.a;
        if (cVar == null || hVar == null) {
            return;
        }
        Matrix matrix = this.x;
        matrix.reset();
        if (!getBounds().isEmpty()) {
            matrix.preTranslate(r3.left, r3.top);
            matrix.preScale(r3.width() / hVar.k.width(), r3.height() / hVar.k.height());
        }
        cVar.c(canvas, matrix, this.p, null);
    }

    @Override // android.graphics.drawable.Drawable
    public final int getAlpha() {
        return this.p;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicHeight() {
        h hVar = this.a;
        if (hVar == null) {
            return -1;
        }
        return hVar.k.height();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicWidth() {
        h hVar = this.a;
        if (hVar == null) {
            return -1;
        }
        return hVar.k.width();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    public final Context h() {
        Drawable.Callback callback = getCallback();
        if (callback != null && (callback instanceof View)) {
            return ((View) callback).getContext();
        }
        return null;
    }

    public final com.quizlet.data.interactor.folderwithcreator.m i() {
        if (getCallback() == null) {
            return null;
        }
        if (this.i == null) {
            Drawable.Callback callback = getCallback();
            com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
            mVar.a = new com.quizlet.data.repository.explanations.myexplanations.a(6, false);
            mVar.b = new HashMap();
            mVar.c = new HashMap();
            mVar.e = ".ttf";
            if (callback instanceof View) {
                mVar.d = ((View) callback).getContext().getAssets();
            } else {
                com.airbnb.lottie.utils.c.b("LottieDrawable must be inside of a view for images to work.");
                mVar.d = null;
            }
            this.i = mVar;
            String str = this.k;
            if (str != null) {
                mVar.e = str;
            }
        }
        return this.i;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void invalidateDrawable(Drawable drawable) {
        Drawable.Callback callback = getCallback();
        if (callback == null) {
            return;
        }
        callback.invalidateDrawable(this);
    }

    @Override // android.graphics.drawable.Drawable
    public final void invalidateSelf() {
        if (this.K) {
            return;
        }
        this.K = true;
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.invalidateDrawable(this);
        }
    }

    @Override // android.graphics.drawable.Animatable
    public final boolean isRunning() {
        com.airbnb.lottie.utils.e eVar = this.b;
        if (eVar == null) {
            return false;
        }
        return eVar.m;
    }

    public final void j() {
        this.f.clear();
        com.airbnb.lottie.utils.e eVar = this.b;
        eVar.h(true);
        Iterator it2 = eVar.c.iterator();
        while (it2.hasNext()) {
            ((Animator.AnimatorPauseListener) it2.next()).onAnimationPause(eVar);
        }
        if (isVisible()) {
            return;
        }
        this.X = 1;
    }

    public final void k() {
        if (this.o == null) {
            this.f.add(new r(this, 1));
            return;
        }
        e();
        boolean zB = b(h());
        com.airbnb.lottie.utils.e eVar = this.b;
        if (zB || eVar.getRepeatCount() == 0) {
            if (isVisible()) {
                eVar.m = true;
                boolean zE = eVar.e();
                Iterator it2 = eVar.b.iterator();
                while (it2.hasNext()) {
                    ((Animator.AnimatorListener) it2.next()).onAnimationStart(eVar, zE);
                }
                eVar.i((int) (eVar.e() ? eVar.c() : eVar.d()));
                eVar.f = 0L;
                eVar.i = 0;
                if (eVar.m) {
                    eVar.h(false);
                    Choreographer.getInstance().postFrameCallback(eVar);
                }
                this.X = 1;
            } else {
                this.X = 2;
            }
        }
        if (b(h())) {
            return;
        }
        Iterator it3 = Y.iterator();
        com.airbnb.lottie.model.h hVarD = null;
        while (it3.hasNext()) {
            hVarD = this.a.d((String) it3.next());
            if (hVarD != null) {
                break;
            }
        }
        if (hVarD != null) {
            o((int) hVarD.b);
        } else {
            o((int) (eVar.d < DefinitionKt.NO_Float_VALUE ? eVar.d() : eVar.c()));
        }
        eVar.h(true);
        eVar.f(eVar.e());
        if (isVisible()) {
            return;
        }
        this.X = 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x00d5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(android.graphics.Canvas r11, com.airbnb.lottie.model.layer.c r12) {
        /*
            Method dump skipped, instructions count: 458
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.u.l(android.graphics.Canvas, com.airbnb.lottie.model.layer.c):void");
    }

    public final void m() {
        if (this.o == null) {
            this.f.add(new r(this, 0));
            return;
        }
        e();
        boolean zB = b(h());
        com.airbnb.lottie.utils.e eVar = this.b;
        if (zB || eVar.getRepeatCount() == 0) {
            if (isVisible()) {
                eVar.m = true;
                eVar.h(false);
                Choreographer.getInstance().postFrameCallback(eVar);
                eVar.f = 0L;
                if (eVar.e() && eVar.h == eVar.d()) {
                    eVar.i(eVar.c());
                } else if (!eVar.e() && eVar.h == eVar.c()) {
                    eVar.i(eVar.d());
                }
                Iterator it2 = eVar.c.iterator();
                while (it2.hasNext()) {
                    ((Animator.AnimatorPauseListener) it2.next()).onAnimationResume(eVar);
                }
                this.X = 1;
            } else {
                this.X = 3;
            }
        }
        if (b(h())) {
            return;
        }
        o((int) (eVar.d < DefinitionKt.NO_Float_VALUE ? eVar.d() : eVar.c()));
        eVar.h(true);
        eVar.f(eVar.e());
        if (isVisible()) {
            return;
        }
        this.X = 1;
    }

    public final boolean n(h hVar) {
        if (this.a == hVar) {
            return false;
        }
        this.K = true;
        d();
        this.a = hVar;
        c();
        com.airbnb.lottie.utils.e eVar = this.b;
        boolean z = eVar.l == null;
        eVar.l = hVar;
        if (z) {
            eVar.k(Math.max(eVar.j, hVar.l), Math.min(eVar.k, hVar.m));
        } else {
            eVar.k((int) hVar.l, (int) hVar.m);
        }
        float f = eVar.h;
        eVar.h = DefinitionKt.NO_Float_VALUE;
        eVar.g = DefinitionKt.NO_Float_VALUE;
        eVar.i((int) f);
        eVar.g();
        u(eVar.getAnimatedFraction());
        ArrayList arrayList = this.f;
        Iterator it2 = new ArrayList(arrayList).iterator();
        while (it2.hasNext()) {
            t tVar = (t) it2.next();
            if (tVar != null) {
                tVar.run();
            }
            it2.remove();
        }
        arrayList.clear();
        hVar.a.a = this.q;
        e();
        Drawable.Callback callback = getCallback();
        if (callback instanceof ImageView) {
            ImageView imageView = (ImageView) callback;
            imageView.setImageDrawable(null);
            imageView.setImageDrawable(this);
        }
        return true;
    }

    public final void o(int i) {
        if (this.a == null) {
            this.f.add(new n(this, i, 2));
        } else {
            this.b.i(i);
        }
    }

    public final void p(int i) {
        if (this.a == null) {
            this.f.add(new n(this, i, 0));
            return;
        }
        com.airbnb.lottie.utils.e eVar = this.b;
        eVar.k(eVar.j, i + 0.99f);
    }

    public final void q(String str) {
        h hVar = this.a;
        if (hVar == null) {
            this.f.add(new m(this, str, 1));
            return;
        }
        com.airbnb.lottie.model.h hVarD = hVar.d(str);
        if (hVarD == null) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Cannot find marker with name ", str, "."));
        }
        p((int) (hVarD.b + hVarD.c));
    }

    public final void r(String str) {
        h hVar = this.a;
        ArrayList arrayList = this.f;
        if (hVar == null) {
            arrayList.add(new m(this, str, 0));
            return;
        }
        com.airbnb.lottie.model.h hVarD = hVar.d(str);
        if (hVarD == null) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Cannot find marker with name ", str, "."));
        }
        int i = (int) hVarD.b;
        int i2 = ((int) hVarD.c) + i;
        if (this.a == null) {
            arrayList.add(new q(this, i, i2));
        } else {
            this.b.k(i, i2 + 0.99f);
        }
    }

    public final void s(int i) {
        if (this.a == null) {
            this.f.add(new n(this, i, 1));
        } else {
            this.b.k(i, (int) r0.k);
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void scheduleDrawable(Drawable drawable, Runnable runnable, long j) {
        Drawable.Callback callback = getCallback();
        if (callback == null) {
            return;
        }
        callback.scheduleDrawable(this, runnable, j);
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        this.p = i;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
        com.airbnb.lottie.utils.c.b("Use addColorFilter instead.");
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean setVisible(boolean z, boolean z2) {
        boolean zIsVisible = isVisible();
        boolean visible = super.setVisible(z, z2);
        if (z) {
            int i = this.X;
            if (i == 2) {
                k();
                return visible;
            }
            if (i == 3) {
                m();
                return visible;
            }
        } else {
            if (this.b.m) {
                j();
                this.X = 3;
                return visible;
            }
            if (zIsVisible) {
                this.X = 1;
            }
        }
        return visible;
    }

    @Override // android.graphics.drawable.Animatable
    public final void start() {
        Drawable.Callback callback = getCallback();
        if ((callback instanceof View) && ((View) callback).isInEditMode()) {
            return;
        }
        k();
    }

    @Override // android.graphics.drawable.Animatable
    public final void stop() {
        this.f.clear();
        com.airbnb.lottie.utils.e eVar = this.b;
        eVar.h(true);
        eVar.f(eVar.e());
        if (isVisible()) {
            return;
        }
        this.X = 1;
    }

    public final void t(String str) {
        h hVar = this.a;
        if (hVar == null) {
            this.f.add(new m(this, str, 2));
            return;
        }
        com.airbnb.lottie.model.h hVarD = hVar.d(str);
        if (hVarD == null) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Cannot find marker with name ", str, "."));
        }
        s((int) hVarD.b);
    }

    public final void u(float f) {
        h hVar = this.a;
        if (hVar == null) {
            this.f.add(new p(this, f, 2));
        } else {
            this.b.i(com.airbnb.lottie.utils.g.f(hVar.l, hVar.m, f));
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        Drawable.Callback callback = getCallback();
        if (callback == null) {
            return;
        }
        callback.unscheduleDrawable(this, runnable);
    }

    public final boolean v() {
        h hVar = this.a;
        if (hVar == null) {
            return false;
        }
        float f = this.W;
        float fB = this.b.b();
        this.W = fB;
        return Math.abs(fB - f) * hVar.b() >= 50.0f;
    }
}
