package com.quizlet.scandocument.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PointF;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import com.davemorrissey.labs.subscaleview.ImageSource;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.quizletandroid.R;
import com.quizlet.scandocument.model.h;
import com.quizlet.scandocument.model.i;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class OcrImageView extends SubsamplingScaleImageView implements View.OnTouchListener {
    public h a;
    public final Paint b;
    public final Paint c;
    public final Paint d;
    public final Paint e;
    public final Path f;
    public final PointF g;
    public PointF h;
    public final ArrayList i;
    public final ArrayList j;
    public PointF k;
    public PointF l;
    public com.quizlet.scandocument.model.b m;
    public final io.reactivex.rxjava3.subjects.d n;
    public TreeSet o;
    public TreeSet p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public OcrImageView(@NotNull Context context, @NotNull AttributeSet attr) {
        super(context, attr);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attr, "attr");
        this.f = new Path();
        this.g = new PointF();
        this.h = new PointF();
        this.i = new ArrayList();
        this.j = new ArrayList();
        this.m = com.quizlet.scandocument.model.b.a;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.n = dVarZ;
        Paint paint = new Paint();
        paint.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.ocrImageAnnotationColor));
        paint.setAntiAlias(true);
        Paint.Style style = Paint.Style.STROKE;
        paint.setStyle(style);
        paint.setStrokeWidth(4.0f);
        this.b = paint;
        Paint paint2 = new Paint();
        paint2.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.ocrImageAnnotationSelectedColor));
        paint2.setAntiAlias(true);
        paint2.setStyle(style);
        paint2.setStrokeWidth(4.0f);
        this.c = paint2;
        Paint paint3 = new Paint();
        paint3.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.ocrImageAnnotationVisitedColor));
        paint3.setAntiAlias(true);
        paint3.setStyle(style);
        paint3.setStrokeWidth(4.0f);
        this.d = paint3;
        Paint paint4 = new Paint();
        paint4.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.ocrImageSelectionColor));
        paint4.setStyle(style);
        paint4.setStrokeCap(Paint.Cap.ROUND);
        paint4.setStrokeWidth(20.0f);
        paint4.setAlpha(150);
        this.e = paint4;
    }

    public final void a() {
        this.j.clear();
        this.i.clear();
        invalidate();
    }

    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object, java.util.List] */
    @Override // com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView, android.view.View
    public final void onDraw(Canvas canvas) throws Throwable {
        Paint paint;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        if (!isReady()) {
            return;
        }
        h hVar = this.a;
        if (hVar == null) {
            Intrinsics.m("scanDocument");
            throw null;
        }
        ?? r2 = hVar.b.b;
        int size = r2.size();
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = 1;
            if (i2 < size) {
                ArrayList arrayList = ((com.quizlet.scandocument.model.c) r2.get(i2)).b.a;
                PointF leftTop = sourceToViewCoord(((i) arrayList.get(0)).a, ((i) arrayList.get(0)).b);
                PointF rightTop = sourceToViewCoord(((i) arrayList.get(1)).a, ((i) arrayList.get(1)).b);
                PointF rightBottom = sourceToViewCoord(((i) arrayList.get(2)).a, ((i) arrayList.get(2)).b);
                PointF leftBottom = sourceToViewCoord(((i) arrayList.get(3)).a, ((i) arrayList.get(3)).b);
                Object[] objects = {leftTop, rightTop, rightBottom, leftBottom};
                Intrinsics.checkNotNullParameter(objects, "objects");
                int i4 = 0;
                while (true) {
                    if (i4 >= 4) {
                        Intrinsics.d(leftTop);
                        Intrinsics.d(rightTop);
                        Intrinsics.d(rightBottom);
                        Intrinsics.d(leftBottom);
                        Intrinsics.checkNotNullParameter(leftTop, "leftTop");
                        Intrinsics.checkNotNullParameter(rightTop, "rightTop");
                        Intrinsics.checkNotNullParameter(rightBottom, "rightBottom");
                        Intrinsics.checkNotNullParameter(leftBottom, "leftBottom");
                        Path path = new Path();
                        path.moveTo(leftTop.x, leftTop.y);
                        path.lineTo(rightTop.x, rightTop.y);
                        path.lineTo(rightBottom.x, rightBottom.y);
                        path.lineTo(leftBottom.x, leftBottom.y);
                        path.lineTo(leftTop.x, leftTop.y);
                        TreeSet treeSet = this.o;
                        if (treeSet == null) {
                            Intrinsics.m("selectedIndexes");
                            throw null;
                        }
                        if (treeSet.contains(Integer.valueOf(i2))) {
                            paint = this.c;
                        } else {
                            TreeSet treeSet2 = this.p;
                            if (treeSet2 == null) {
                                Intrinsics.m("visitedIndexes");
                                throw null;
                            }
                            paint = treeSet2.contains(Integer.valueOf(i2)) ? this.d : this.b;
                        }
                        canvas.drawPath(path, paint);
                    } else {
                        if (objects[i4] == null) {
                            timber.log.c.a.e(new IllegalArgumentException("Couldn't convert annotation coordinates to view coordinates"));
                            break;
                        }
                        i4++;
                    }
                }
                i2++;
            } else {
                ArrayList arrayList2 = this.i;
                int size2 = arrayList2.size();
                Paint paint2 = this.e;
                if (size2 >= 2) {
                    Path path2 = this.f;
                    path2.reset();
                    sourceToViewCoord(((PointF) arrayList2.get(0)).x, ((PointF) arrayList2.get(0)).y, this.h);
                    PointF pointF = this.h;
                    path2.moveTo(pointF.x, pointF.y);
                    int size3 = arrayList2.size() - 1;
                    if (1 <= size3) {
                        int i5 = 1;
                        while (true) {
                            float f = ((PointF) arrayList2.get(i5)).x;
                            float f2 = ((PointF) arrayList2.get(i5)).y;
                            PointF pointF2 = this.g;
                            sourceToViewCoord(f, f2, pointF2);
                            PointF pointF3 = this.h;
                            float f3 = pointF3.x;
                            float f4 = pointF3.y;
                            float f5 = 2;
                            path2.quadTo(f3, f4, (pointF2.x + f3) / f5, (pointF2.y + f4) / f5);
                            this.h = pointF2;
                            if (i5 == size3) {
                                break;
                            } else {
                                i5++;
                            }
                        }
                    }
                    canvas.drawPath(path2, paint2);
                }
                ArrayList arrayList3 = this.j;
                int size4 = arrayList3.size() - 1;
                if (size4 < 0) {
                    return;
                }
                int i6 = 0;
                while (true) {
                    if (!((List) arrayList3.get(i6)).isEmpty()) {
                        if (((List) arrayList3.get(i6)).size() == i3) {
                            PointF pointFSourceToViewCoord = sourceToViewCoord((PointF) ((List) arrayList3.get(i6)).get(i));
                            Intrinsics.d(pointFSourceToViewCoord);
                            canvas.drawPoint(pointFSourceToViewCoord.x, pointFSourceToViewCoord.y, paint2);
                        } else {
                            Path path3 = new Path();
                            PointF pointF4 = new PointF();
                            sourceToViewCoord(((PointF) ((List) arrayList3.get(i6)).get(i)).x, ((PointF) ((List) arrayList3.get(i6)).get(i)).y, pointF4);
                            path3.moveTo(pointF4.x, pointF4.y);
                            int size5 = ((List) arrayList3.get(i6)).size();
                            int i7 = i3;
                            while (i7 < size5) {
                                PointF pointF5 = new PointF();
                                sourceToViewCoord(((PointF) ((List) arrayList3.get(i6)).get(i7)).x, ((PointF) ((List) arrayList3.get(i6)).get(i7)).y, pointF5);
                                float f6 = pointF4.x;
                                float f7 = pointF4.y;
                                float f8 = 2;
                                path3.quadTo(f6, f7, (pointF5.x + f6) / f8, (pointF5.y + f7) / f8);
                                i7++;
                                pointF4 = pointF5;
                            }
                            canvas.drawPath(path3, paint2);
                        }
                    }
                    if (i6 == size4) {
                        return;
                    }
                    i6++;
                    i = 0;
                    i3 = 1;
                }
            }
        }
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent motionEvent) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(motionEvent, "motionEvent");
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0072  */
    @Override // com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onTouchEvent(android.view.MotionEvent r9) {
        /*
            r8 = this;
            java.lang.String r0 = "event"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            com.quizlet.scandocument.model.b r0 = r8.m
            com.quizlet.scandocument.model.b r1 = com.quizlet.scandocument.model.b.b
            if (r0 != r1) goto L10
            boolean r9 = super.onTouchEvent(r9)
            return r9
        L10:
            int r0 = r9.getActionMasked()
            java.util.ArrayList r1 = r8.i
            r2 = 1
            r3 = 0
            if (r0 == 0) goto L9f
            io.reactivex.rxjava3.subjects.d r4 = r8.n
            if (r0 == r2) goto L72
            r5 = 2
            if (r0 == r5) goto L26
            r5 = 6
            if (r0 == r5) goto L72
            goto Ld4
        L26:
            float r0 = r9.getX()
            float r3 = r9.getY()
            android.graphics.PointF r0 = r8.viewToSourceCoord(r0, r3)
            if (r0 == 0) goto Ld4
            android.graphics.PointF r3 = r8.l
            android.graphics.PointF r5 = r8.k
            if (r3 == 0) goto Ld4
            if (r5 == 0) goto Ld4
            float r3 = r9.getX()
            float r6 = r5.x
            float r3 = r3 - r6
            float r3 = java.lang.Math.abs(r3)
            float r6 = r9.getY()
            float r7 = r5.y
            float r6 = r6 - r7
            float r6 = java.lang.Math.abs(r6)
            r7 = 1101004800(0x41a00000, float:20.0)
            int r3 = (r3 > r7 ? 1 : (r3 == r7 ? 0 : -1))
            if (r3 >= 0) goto L5c
            int r3 = (r6 > r7 ? 1 : (r6 == r7 ? 0 : -1))
            if (r3 < 0) goto L6e
        L5c:
            r1.add(r0)
            float r1 = r9.getX()
            r5.x = r1
            float r9 = r9.getY()
            r5.y = r9
            r4.b(r0)
        L6e:
            r8.invalidate()
            goto Lda
        L72:
            float r0 = r9.getX()
            float r5 = r9.getY()
            android.graphics.PointF r0 = r8.viewToSourceCoord(r0, r5)
            if (r0 == 0) goto L83
            r4.b(r0)
        L83:
            java.util.ArrayList r0 = r8.j
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>(r1)
            r0.add(r4)
            r1.clear()
            r8.invalidate()
            android.graphics.PointF r0 = new android.graphics.PointF
            r0.<init>()
            r8.h = r0
            r8.k = r3
            r8.l = r3
            goto Ld4
        L9f:
            int r0 = r9.getActionIndex()
            if (r0 != 0) goto Ld0
            float r0 = r9.getX()
            float r3 = r9.getY()
            android.graphics.PointF r0 = r8.viewToSourceCoord(r0, r3)
            r8.l = r0
            android.graphics.PointF r0 = new android.graphics.PointF
            float r3 = r9.getX()
            float r4 = r9.getY()
            r0.<init>(r3, r4)
            r8.k = r0
            boolean r0 = r1.isEmpty()
            if (r0 == 0) goto Ld4
            android.graphics.PointF r0 = r8.l
            if (r0 == 0) goto Ld4
            r1.add(r0)
            goto Ld4
        Ld0:
            r8.l = r3
            r8.k = r3
        Ld4:
            boolean r9 = super.onTouchEvent(r9)
            if (r9 == 0) goto Ldb
        Lda:
            return r2
        Ldb:
            r9 = 0
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.scandocument.ui.OcrImageView.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public final void setInteractionMode(@NotNull com.quizlet.scandocument.model.b interactionMode) {
        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
        this.m = interactionMode;
        setZoomEnabled(interactionMode != com.quizlet.scandocument.model.b.a);
    }

    public final void setScanDocument(@NotNull h scanDocument) {
        Intrinsics.checkNotNullParameter(scanDocument, "scanDocument");
        this.a = scanDocument;
        setImage(ImageSource.bitmap(scanDocument.a));
    }
}
