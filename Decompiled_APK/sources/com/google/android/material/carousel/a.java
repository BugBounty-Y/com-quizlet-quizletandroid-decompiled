package com.google.android.material.carousel;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import androidx.core.graphics.d;
import androidx.recyclerview.widget.AbstractC1375k0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class a extends AbstractC1375k0 {
    public final Paint a;
    public final List b;

    public a() {
        Paint paint = new Paint();
        this.a = paint;
        this.b = Collections.unmodifiableList(new ArrayList());
        paint.setStrokeWidth(5.0f);
        paint.setColor(-65281);
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void onDrawOver(Canvas canvas, RecyclerView recyclerView, B0 b0) {
        Canvas canvas2;
        super.onDrawOver(canvas, recyclerView, b0);
        Paint paint = this.a;
        paint.setStrokeWidth(recyclerView.getResources().getDimension(R.dimen.m3_carousel_debug_keyline_width));
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            ((c) it2.next()).getClass();
            ThreadLocal threadLocal = d.a;
            float f = 1.0f - DefinitionKt.NO_Float_VALUE;
            paint.setColor(Color.argb((int) ((Color.alpha(-16776961) * DefinitionKt.NO_Float_VALUE) + (Color.alpha(-65281) * f)), (int) ((Color.red(-16776961) * DefinitionKt.NO_Float_VALUE) + (Color.red(-65281) * f)), (int) ((Color.green(-16776961) * DefinitionKt.NO_Float_VALUE) + (Color.green(-65281) * f)), (int) ((Color.blue(-16776961) * DefinitionKt.NO_Float_VALUE) + (Color.blue(-65281) * f))));
            if (((CarouselLayoutManager) recyclerView.getLayoutManager()).I0()) {
                canvas2 = canvas;
                canvas2.drawLine(DefinitionKt.NO_Float_VALUE, ((CarouselLayoutManager) recyclerView.getLayoutManager()).q.f(), DefinitionKt.NO_Float_VALUE, ((CarouselLayoutManager) recyclerView.getLayoutManager()).q.b(), paint);
            } else {
                canvas2 = canvas;
                canvas2.drawLine(((CarouselLayoutManager) recyclerView.getLayoutManager()).q.c(), DefinitionKt.NO_Float_VALUE, ((CarouselLayoutManager) recyclerView.getLayoutManager()).q.d(), DefinitionKt.NO_Float_VALUE, paint);
            }
            canvas = canvas2;
        }
    }
}
