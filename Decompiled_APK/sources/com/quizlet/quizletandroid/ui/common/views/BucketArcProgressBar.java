package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import com.quizlet.quizletandroid.I;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BucketArcProgressBar extends View {
    public final ArrayList a;
    public final RectF b;
    public float c;
    public float d;
    public float e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BucketArcProgressBar(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = new ArrayList();
        this.b = new RectF();
        b(null);
    }

    public final void a(float f, int i) {
        if (f <= DefinitionKt.NO_Float_VALUE) {
            return;
        }
        this.e += f;
        ArrayList arrayList = this.a;
        Paint paint = new Paint();
        paint.setAntiAlias(true);
        paint.setColor(i);
        paint.setStrokeWidth(this.d);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.BUTT);
        arrayList.add(new a(f, paint));
        invalidate();
    }

    public final void b(AttributeSet attributeSet) {
        this.c = getResources().getDimension(R.dimen.bucketarcprogressbar_default_bucket_spacing);
        this.d = getResources().getDimension(R.dimen.bucketarcprogressbar_default_stroke_width);
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, I.b);
            this.c = typedArrayObtainStyledAttributes.getDimension(1, this.c);
            this.d = typedArrayObtainStyledAttributes.getDimension(2, this.d);
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        float fMin = Math.min(getWidth(), getHeight()) - this.d;
        float f = 2;
        float width = (this.d / f) + ((getWidth() - r0) / 2);
        float height = (this.d / f) + ((getHeight() - r0) / 2);
        RectF rectF = this.b;
        rectF.set(width, height, width + fMin, height + fMin);
        float f2 = (360 * this.c) / ((fMin / f) * 6.2831855f);
        ArrayList arrayList = this.a;
        float size = (arrayList.size() - 1) * f2;
        int size2 = arrayList.size();
        float f3 = 180.0f;
        for (int i = 0; i < size2; i++) {
            float fRound = Math.round((180.0f - size) * (((a) arrayList.get(i)).a / this.e));
            canvas.drawArc(rectF, f3, fRound, false, ((a) arrayList.get(i)).b);
            f3 += fRound + f2;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BucketArcProgressBar(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        this.a = new ArrayList();
        this.b = new RectF();
        b(attrs);
    }
}
