package org.wordpress.aztec.toolbar;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Toast;
import androidx.appcompat.widget.C0090i0;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RippleToggleButton extends C0090i0 implements View.OnLongClickListener {
    public float d;
    public boolean e;
    public int f;
    public Paint g;
    public Paint h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RippleToggleButton(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        a();
    }

    public final void a() {
        if (isInEditMode()) {
            return;
        }
        setOnLongClickListener(this);
        int color = getContext().getColor(R.color.format_bar_ripple_animation);
        Paint paint = new Paint();
        this.g = paint;
        paint.setAntiAlias(true);
        Paint paint2 = this.g;
        Intrinsics.d(paint2);
        paint2.setColor(color);
        Paint paint3 = this.g;
        Intrinsics.d(paint3);
        paint3.setStyle(Paint.Style.FILL);
        Paint paint4 = this.g;
        Intrinsics.d(paint4);
        paint4.setAlpha(200);
        Paint paint5 = new Paint();
        this.h = paint5;
        paint5.setAntiAlias(true);
        Paint paint6 = this.h;
        Intrinsics.d(paint6);
        paint6.setColor(color);
        Paint paint7 = this.h;
        Intrinsics.d(paint7);
        paint7.setStyle(Paint.Style.STROKE);
        Paint paint8 = this.h;
        Intrinsics.d(paint8);
        paint8.setStrokeWidth(2.0f);
        Paint paint9 = this.h;
        Intrinsics.d(paint9);
        paint9.setAlpha(255);
        setWillNotDraw(false);
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.draw(canvas);
        if (this.e) {
            int i = this.f;
            if (250 <= i * 10) {
                this.e = false;
                this.f = 0;
            } else {
                float f = (i * 10) / 250;
                Paint paint = this.g;
                Intrinsics.d(paint);
                float f2 = 1 - f;
                paint.setAlpha((int) (200 * f2));
                Paint paint2 = this.h;
                Intrinsics.d(paint2);
                paint2.setAlpha((int) (255 * f2));
                float f3 = this.d;
                Paint paint3 = this.g;
                Intrinsics.d(paint3);
                canvas.drawCircle(f3, f3, f3 * f, paint3);
                float f4 = this.d;
                Paint paint4 = this.h;
                Intrinsics.d(paint4);
                canvas.drawCircle(f4, f4, f * f4, paint4);
                this.f++;
            }
            invalidate();
        }
    }

    @Override // android.view.View.OnLongClickListener
    public final boolean onLongClick(View view) {
        if (getContentDescription() == null || D.l(getContentDescription().toString(), "", true)) {
            return false;
        }
        Toast.makeText(getContext(), getContentDescription(), 0).show();
        return true;
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onTouchEvent(MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (isEnabled() && !this.e) {
            this.d = getMeasuredWidth() / 2;
            this.e = true;
            invalidate();
        }
        return super.onTouchEvent(event);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RippleToggleButton(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        a();
    }
}
