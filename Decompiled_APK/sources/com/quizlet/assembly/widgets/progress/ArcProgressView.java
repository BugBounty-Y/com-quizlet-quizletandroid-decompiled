package com.quizlet.assembly.widgets.progress;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import androidx.compose.runtime.snapshots.C;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.W;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ArcProgressView extends View {
    public d a;
    public float b;
    public ArrayList c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ArcProgressView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final RectF getOval() {
        float stroke = getStroke();
        float stroke2 = getStroke();
        float f = this.b;
        return new RectF(stroke, stroke2, f, f);
    }

    private final float getStroke() {
        return this.b / 10;
    }

    public final Paint a(int i) {
        Paint paint = new Paint();
        paint.setStrokeWidth(getStroke());
        paint.setAntiAlias(true);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.ROUND);
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        paint.setColor(com.quizlet.themes.extensions.a.a(context, i));
        return paint;
    }

    public final d getState() {
        return this.a;
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        int i;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        d dVar = this.a;
        if (dVar == null) {
            return;
        }
        List<c> list = dVar.a;
        if (!list.isEmpty()) {
            this.c.clear();
            boolean zC = dVar.c();
            int i2 = R.attr.KnowArcColor;
            if (zC) {
                int iOrdinal = ((c) list.get(0)).c.ordinal();
                if (iOrdinal != 0) {
                    if (iOrdinal == 1) {
                        i2 = R.attr.StillLearningArcColor;
                    } else {
                        if (iOrdinal != 2) {
                            throw new NoWhenBranchMatchedException();
                        }
                        i2 = R.attr.LeftArcColor;
                    }
                }
                this.c = B.f(a(i2));
            } else {
                for (c cVar : list) {
                    ArrayList arrayList = this.c;
                    int iOrdinal2 = cVar.c.ordinal();
                    if (iOrdinal2 == 0) {
                        i = R.attr.KnowArcColor;
                    } else if (iOrdinal2 == 1) {
                        i = R.attr.StillLearningArcColor;
                    } else {
                        if (iOrdinal2 != 2) {
                            throw new NoWhenBranchMatchedException();
                        }
                        i = R.attr.LeftArcColor;
                    }
                    arrayList.add(a(i));
                }
            }
        }
        if (dVar.c()) {
            Object obj = this.c.get(0);
            Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
            canvas.drawArc(getOval(), 270.0f, 360.0f, false, (Paint) obj);
            return;
        }
        int iB = dVar.b();
        Intrinsics.checkNotNullParameter(list, "<this>");
        Iterator it2 = new W(list).iterator();
        int i3 = 0;
        while (true) {
            ListIterator listIterator = (ListIterator) ((C) it2).b;
            if (!listIterator.hasPrevious()) {
                return;
            }
            Object objPrevious = listIterator.previous();
            int i4 = i3 + 1;
            if (i3 < 0) {
                B.p();
                throw null;
            }
            Object obj2 = this.c.get(list.indexOf((c) objPrevious));
            Intrinsics.checkNotNullExpressionValue(obj2, "get(...)");
            Paint paint = (Paint) obj2;
            float f = iB;
            float f2 = (r2.b * 360.0f) / f;
            Iterator it3 = CollectionsKt.I(i4, list).iterator();
            int i5 = 0;
            while (it3.hasNext()) {
                i5 += ((c) it3.next()).b;
            }
            canvas.drawArc(getOval(), ((i5 * 360.0f) / f) - 90.0f, f2, false, paint);
            i3 = i4;
        }
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        int mode = View.MeasureSpec.getMode(i);
        if (mode != Integer.MIN_VALUE && mode != 1073741824) {
            setMeasuredDimension((int) (getStroke() + this.b), (int) (getStroke() + this.b));
            return;
        }
        int size = View.MeasureSpec.getSize(i);
        float f = size;
        this.b = f - (f / 10.0f);
        setMeasuredDimension(size, size);
    }

    public final void setState(d dVar) {
        this.a = dVar;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ArcProgressView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public ArcProgressView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        this.b = 300.0f;
        this.c = new ArrayList();
    }
}
