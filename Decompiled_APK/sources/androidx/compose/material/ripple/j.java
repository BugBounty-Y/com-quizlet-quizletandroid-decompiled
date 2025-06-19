package androidx.compose.material.ripple;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.View;
import android.view.animation.AnimationUtils;
import androidx.activity.RunnableC0041m;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class j extends View {
    public static final int[] f = {R.attr.state_pressed, R.attr.state_enabled};
    public static final int[] g = new int[0];
    public s a;
    public Boolean b;
    public Long c;
    public RunnableC0041m d;
    public kotlin.jvm.internal.r e;

    public j(@NotNull Context context) {
        super(context);
    }

    private final void setRippleState(boolean z) {
        long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
        Runnable runnable = this.d;
        if (runnable != null) {
            removeCallbacks(runnable);
            runnable.run();
        }
        Long l = this.c;
        long jLongValue = jCurrentAnimationTimeMillis - (l != null ? l.longValue() : 0L);
        if (z || jLongValue >= 5) {
            int[] iArr = z ? f : g;
            s sVar = this.a;
            if (sVar != null) {
                sVar.setState(iArr);
            }
        } else {
            RunnableC0041m runnableC0041m = new RunnableC0041m(this, 26);
            this.d = runnableC0041m;
            postDelayed(runnableC0041m, 50L);
        }
        this.c = Long.valueOf(jCurrentAnimationTimeMillis);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setRippleState$lambda$2(j jVar) {
        s sVar = jVar.a;
        if (sVar != null) {
            sVar.setState(g);
        }
        jVar.d = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(androidx.compose.foundation.interaction.o oVar, boolean z, long j, int i, long j2, float f2, Function0 function0) {
        if (this.a == null || !Boolean.valueOf(z).equals(this.b)) {
            s sVar = new s(z);
            setBackground(sVar);
            this.a = sVar;
            this.b = Boolean.valueOf(z);
        }
        s sVar2 = this.a;
        Intrinsics.d(sVar2);
        this.e = (kotlin.jvm.internal.r) function0;
        e(j, i, j2, f2);
        if (z) {
            sVar2.setHotspot(androidx.compose.ui.geometry.b.d(oVar.a), androidx.compose.ui.geometry.b.e(oVar.a));
        } else {
            sVar2.setHotspot(sVar2.getBounds().centerX(), sVar2.getBounds().centerY());
        }
        setRippleState(true);
    }

    public final void c() {
        this.e = null;
        RunnableC0041m runnableC0041m = this.d;
        if (runnableC0041m != null) {
            removeCallbacks(runnableC0041m);
            RunnableC0041m runnableC0041m2 = this.d;
            Intrinsics.d(runnableC0041m2);
            runnableC0041m2.run();
        } else {
            s sVar = this.a;
            if (sVar != null) {
                sVar.setState(g);
            }
        }
        s sVar2 = this.a;
        if (sVar2 == null) {
            return;
        }
        sVar2.setVisible(false, false);
        unscheduleDrawable(sVar2);
    }

    public final void d() {
        setRippleState(false);
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        if (isAttachedToWindow()) {
            super.draw(canvas);
        } else {
            c();
        }
    }

    public final void e(long j, int i, long j2, float f2) {
        s sVar = this.a;
        if (sVar == null) {
            return;
        }
        Integer num = sVar.c;
        if (num == null || num.intValue() != i) {
            sVar.c = Integer.valueOf(i);
            sVar.setRadius(i);
        }
        if (Build.VERSION.SDK_INT < 28) {
            f2 *= 2;
        }
        if (f2 > 1.0f) {
            f2 = 1.0f;
        }
        long jB = C0861v.b(j2, f2);
        C0861v c0861v = sVar.b;
        if (!(c0861v == null ? false : C0861v.c(c0861v.a, jB))) {
            sVar.b = new C0861v(jB);
            sVar.setColor(ColorStateList.valueOf(F.A(jB)));
        }
        Rect rect = new Rect(0, 0, kotlin.math.c.b(androidx.compose.ui.geometry.e.d(j)), kotlin.math.c.b(androidx.compose.ui.geometry.e.b(j)));
        setLeft(rect.left);
        setTop(rect.top);
        setRight(rect.right);
        setBottom(rect.bottom);
        sVar.setBounds(rect);
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // android.view.View, android.graphics.drawable.Drawable.Callback
    public final void invalidateDrawable(Drawable drawable) {
        ?? r1 = this.e;
        if (r1 != 0) {
            r1.invoke();
        }
    }

    @Override // android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        setMeasuredDimension(0, 0);
    }

    @Override // android.view.View
    public final void refreshDrawableState() {
    }
}
