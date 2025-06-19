package com.quizlet.baserecyclerview.decoration;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1375k0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.C1383o0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class c extends AbstractC1375k0 {
    public final Paint a;
    public final int b;
    public final int c;
    public final b d;
    public final int e;

    public c(Context context, int i, int i2, b bVar) {
        this.d = b.Z0;
        Paint paint = new Paint();
        this.a = paint;
        paint.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.dividerColor));
        int dimension = (int) context.getResources().getDimension(R.dimen.divider_item_width);
        this.b = dimension;
        paint.setStrokeWidth(dimension);
        if ((i & 3) == 0) {
            throw new IllegalArgumentException("invalid orientation");
        }
        this.e = i;
        this.c = i2;
        this.d = bVar;
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, B0 b0) {
        int i = this.e & 1;
        int i2 = this.b;
        if (i == 1) {
            rect.set(0, 0, 0, i2);
        } else {
            rect.set(0, 0, i2, 0);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void onDrawOver(Canvas canvas, RecyclerView recyclerView, B0 b0) {
        int i = this.e & 1;
        Paint paint = this.a;
        b bVar = this.d;
        int i2 = this.c;
        if (i == 1) {
            int paddingStart = recyclerView.getPaddingStart();
            int width = recyclerView.getWidth() - recyclerView.getPaddingEnd();
            int childCount = recyclerView.getChildCount();
            for (int i3 = 0; i3 < childCount; i3++) {
                View childAt = recyclerView.getChildAt(i3);
                F0 f0P = RecyclerView.P(childAt);
                if (bVar.z(f0P != null ? f0P.getAbsoluteAdapterPosition() : -1)) {
                    float bottom = childAt.getBottom() + ((ViewGroup.MarginLayoutParams) ((C1383o0) childAt.getLayoutParams())).bottomMargin;
                    canvas.drawLine(paddingStart + i2, bottom, width - i2, bottom, paint);
                }
            }
        }
        if ((this.e & 2) == 2) {
            int paddingTop = recyclerView.getPaddingTop();
            int height = recyclerView.getHeight() - recyclerView.getPaddingBottom();
            int childCount2 = recyclerView.getChildCount();
            for (int i4 = 0; i4 < childCount2; i4++) {
                View childAt2 = recyclerView.getChildAt(i4);
                F0 f0P2 = RecyclerView.P(childAt2);
                if (bVar.z(f0P2 != null ? f0P2.getAbsoluteAdapterPosition() : -1)) {
                    float right = childAt2.getRight() + ((ViewGroup.MarginLayoutParams) ((C1383o0) childAt2.getLayoutParams())).rightMargin;
                    canvas.drawLine(right, paddingTop + i2, right, height - i2, paint);
                }
            }
        }
    }
}
