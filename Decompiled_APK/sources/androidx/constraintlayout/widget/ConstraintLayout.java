package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.compose.foundation.lazy.layout.n0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public class ConstraintLayout extends ViewGroup {
    public static v p;
    public SparseArray a;
    public ArrayList b;
    public androidx.constraintlayout.core.widgets.f c;
    public int d;
    public int e;
    public int f;
    public int g;
    public boolean h;
    public int i;
    public o j;
    public n0 k;
    public int l;
    public HashMap m;
    public SparseArray n;
    public f o;

    public ConstraintLayout(@NonNull Context context) throws XmlPullParserException, IOException {
        super(context);
        this.a = new SparseArray();
        this.b = new ArrayList(4);
        this.c = new androidx.constraintlayout.core.widgets.f();
        this.d = 0;
        this.e = 0;
        this.f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.h = true;
        this.i = 257;
        this.j = null;
        this.k = null;
        this.l = -1;
        this.m = new HashMap();
        this.n = new SparseArray();
        this.o = new f(this, this);
        j(null, 0);
    }

    private int getPaddingWidth() {
        int iMax = Math.max(0, getPaddingRight()) + Math.max(0, getPaddingLeft());
        int iMax2 = Math.max(0, getPaddingEnd()) + Math.max(0, getPaddingStart());
        return iMax2 > 0 ? iMax2 : iMax;
    }

    public static v getSharedValues() {
        if (p == null) {
            v vVar = new v();
            new SparseIntArray();
            new HashMap();
            p = vVar;
        }
        return p;
    }

    public final View a(int i) {
        return (View) this.a.get(i);
    }

    public final androidx.constraintlayout.core.widgets.e b(View view) {
        if (view == this) {
            return this.c;
        }
        if (view == null) {
            return null;
        }
        if (view.getLayoutParams() instanceof e) {
            return ((e) view.getLayoutParams()).q0;
        }
        view.setLayoutParams(new e(view.getLayoutParams()));
        if (view.getLayoutParams() instanceof e) {
            return ((e) view.getLayoutParams()).q0;
        }
        return null;
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof e;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        Object tag;
        int size;
        ArrayList arrayList = this.b;
        if (arrayList != null && (size = arrayList.size()) > 0) {
            for (int i = 0; i < size; i++) {
                ((c) arrayList.get(i)).getClass();
            }
        }
        super.dispatchDraw(canvas);
        if (isInEditMode()) {
            float width = getWidth();
            float height = getHeight();
            int childCount = getChildCount();
            for (int i2 = 0; i2 < childCount; i2++) {
                View childAt = getChildAt(i2);
                if (childAt.getVisibility() != 8 && (tag = childAt.getTag()) != null && (tag instanceof String)) {
                    String[] strArrSplit = ((String) tag).split(",");
                    if (strArrSplit.length == 4) {
                        int i3 = Integer.parseInt(strArrSplit[0]);
                        int i4 = Integer.parseInt(strArrSplit[1]);
                        int i5 = Integer.parseInt(strArrSplit[2]);
                        int i6 = (int) ((i3 / 1080.0f) * width);
                        int i7 = (int) ((i4 / 1920.0f) * height);
                        Paint paint = new Paint();
                        paint.setColor(-65536);
                        float f = i6;
                        float f2 = i7;
                        float f3 = i6 + ((int) ((i5 / 1080.0f) * width));
                        canvas.drawLine(f, f2, f3, f2, paint);
                        float f4 = i7 + ((int) ((Integer.parseInt(strArrSplit[3]) / 1920.0f) * height));
                        canvas.drawLine(f3, f2, f3, f4, paint);
                        canvas.drawLine(f3, f4, f, f4, paint);
                        canvas.drawLine(f, f4, f, f2, paint);
                        paint.setColor(-16711936);
                        canvas.drawLine(f, f2, f3, f4, paint);
                        canvas.drawLine(f, f4, f3, f2, paint);
                    }
                }
            }
        }
    }

    @Override // android.view.View
    public final void forceLayout() {
        this.h = true;
        super.forceLayout();
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new e();
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new e(getContext(), attributeSet);
    }

    public int getMaxHeight() {
        return this.g;
    }

    public int getMaxWidth() {
        return this.f;
    }

    public int getMinHeight() {
        return this.e;
    }

    public int getMinWidth() {
        return this.d;
    }

    public int getOptimizationLevel() {
        return this.c.G0;
    }

    public String getSceneString() {
        int id;
        StringBuilder sb = new StringBuilder();
        androidx.constraintlayout.core.widgets.f fVar = this.c;
        if (fVar.k == null) {
            int id2 = getId();
            if (id2 != -1) {
                fVar.k = getContext().getResources().getResourceEntryName(id2);
            } else {
                fVar.k = "parent";
            }
        }
        if (fVar.l0 == null) {
            fVar.l0 = fVar.k;
        }
        Iterator it2 = fVar.t0.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            View view = (View) eVar.i0;
            if (view != null) {
                if (eVar.k == null && (id = view.getId()) != -1) {
                    eVar.k = getContext().getResources().getResourceEntryName(id);
                }
                if (eVar.l0 == null) {
                    eVar.l0 = eVar.k;
                }
            }
        }
        fVar.o(sb);
        return sb.toString();
    }

    public final void j(AttributeSet attributeSet, int i) throws XmlPullParserException, IOException {
        androidx.constraintlayout.core.widgets.f fVar = this.c;
        fVar.i0 = this;
        f fVar2 = this.o;
        fVar.x0 = fVar2;
        fVar.v0.h = fVar2;
        this.a.put(getId(), this);
        this.j = null;
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, u.b, i, 0);
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            for (int i2 = 0; i2 < indexCount; i2++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i2);
                if (index == 16) {
                    this.d = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.d);
                } else if (index == 17) {
                    this.e = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.e);
                } else if (index == 14) {
                    this.f = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.f);
                } else if (index == 15) {
                    this.g = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.g);
                } else if (index == 113) {
                    this.i = typedArrayObtainStyledAttributes.getInt(index, this.i);
                } else if (index == 56) {
                    int resourceId = typedArrayObtainStyledAttributes.getResourceId(index, 0);
                    if (resourceId != 0) {
                        try {
                            l(resourceId);
                        } catch (Resources.NotFoundException unused) {
                            this.k = null;
                        }
                    }
                } else if (index == 34) {
                    int resourceId2 = typedArrayObtainStyledAttributes.getResourceId(index, 0);
                    try {
                        o oVar = new o();
                        this.j = oVar;
                        oVar.i(getContext(), resourceId2);
                    } catch (Resources.NotFoundException unused2) {
                        this.j = null;
                    }
                    this.l = resourceId2;
                }
            }
            typedArrayObtainStyledAttributes.recycle();
        }
        fVar.G0 = this.i;
        androidx.constraintlayout.core.c.q = fVar.c0(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
    }

    public final boolean k() {
        return (getContext().getApplicationInfo().flags & 4194304) != 0 && 1 == getLayoutDirection();
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x007b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void l(int r14) throws org.xmlpull.v1.XmlPullParserException, android.content.res.Resources.NotFoundException, java.io.IOException {
        /*
            r13 = this;
            androidx.compose.foundation.lazy.layout.n0 r0 = new androidx.compose.foundation.lazy.layout.n0
            android.content.Context r1 = r13.getContext()
            r0.<init>()
            r2 = -1
            r0.a = r2
            r0.b = r2
            android.util.SparseArray r3 = new android.util.SparseArray
            r3.<init>()
            r0.d = r3
            android.util.SparseArray r3 = new android.util.SparseArray
            r3.<init>()
            r0.e = r3
            r0.c = r13
            java.lang.String r3 = "Error parsing resource: "
            java.lang.String r4 = "ConstraintLayoutStates"
            android.content.res.Resources r5 = r1.getResources()
            android.content.res.XmlResourceParser r5 = r5.getXml(r14)
            int r6 = r5.getEventType()     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r7 = 0
        L2f:
            r8 = 1
            if (r6 == r8) goto Lc7
            r9 = 2
            if (r6 == r9) goto L37
            goto La3
        L37:
            java.lang.String r6 = r5.getName()     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            int r10 = r6.hashCode()     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r11 = 4
            r12 = 3
            switch(r10) {
                case -1349929691: goto L71;
                case 80204913: goto L67;
                case 1382829617: goto L5e;
                case 1657696882: goto L54;
                case 1901439077: goto L45;
                default: goto L44;
            }     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
        L44:
            goto L7b
        L45:
            java.lang.String r8 = "Variant"
            boolean r6 = r6.equals(r8)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r6 == 0) goto L7b
            r8 = r12
            goto L7c
        L4f:
            r1 = move-exception
            goto La8
        L51:
            r1 = move-exception
            goto Lb8
        L54:
            java.lang.String r8 = "layoutDescription"
            boolean r6 = r6.equals(r8)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r6 == 0) goto L7b
            r8 = 0
            goto L7c
        L5e:
            java.lang.String r10 = "StateSet"
            boolean r6 = r6.equals(r10)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r6 == 0) goto L7b
            goto L7c
        L67:
            java.lang.String r8 = "State"
            boolean r6 = r6.equals(r8)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r6 == 0) goto L7b
            r8 = r9
            goto L7c
        L71:
            java.lang.String r8 = "ConstraintSet"
            boolean r6 = r6.equals(r8)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r6 == 0) goto L7b
            r8 = r11
            goto L7c
        L7b:
            r8 = r2
        L7c:
            if (r8 == r9) goto L94
            if (r8 == r12) goto L87
            if (r8 == r11) goto L83
            goto La3
        L83:
            r0.b(r1, r5)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            goto La3
        L87:
            androidx.constraintlayout.widget.h r6 = new androidx.constraintlayout.widget.h     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r6.<init>(r1, r5)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            if (r7 == 0) goto La3
            java.util.ArrayList r8 = r7.b     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r8.add(r6)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            goto La3
        L94:
            androidx.constraintlayout.widget.g r6 = new androidx.constraintlayout.widget.g     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r6.<init>(r1, r5)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            java.lang.Object r7 = r0.d     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            android.util.SparseArray r7 = (android.util.SparseArray) r7     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            int r8 = r6.a     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r7.put(r8, r6)     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            r7 = r6
        La3:
            int r6 = r5.next()     // Catch: java.io.IOException -> L4f org.xmlpull.v1.XmlPullParserException -> L51
            goto L2f
        La8:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>(r3)
            r2.append(r14)
            java.lang.String r14 = r2.toString()
            android.util.Log.e(r4, r14, r1)
            goto Lc7
        Lb8:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>(r3)
            r2.append(r14)
            java.lang.String r14 = r2.toString()
            android.util.Log.e(r4, r14, r1)
        Lc7:
            r13.k = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.ConstraintLayout.l(int):void");
    }

    public final void m(int i, int i2, int i3, int i4, boolean z, boolean z2) {
        f fVar = this.o;
        int i5 = fVar.e;
        int iResolveSizeAndState = View.resolveSizeAndState(i3 + fVar.d, i, 0);
        int iResolveSizeAndState2 = View.resolveSizeAndState(i4 + i5, i2, 0) & 16777215;
        int iMin = Math.min(this.f, iResolveSizeAndState & 16777215);
        int iMin2 = Math.min(this.g, iResolveSizeAndState2);
        if (z) {
            iMin |= 16777216;
        }
        if (z2) {
            iMin2 |= 16777216;
        }
        setMeasuredDimension(iMin, iMin2);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0113  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(androidx.constraintlayout.core.widgets.f r18, int r19, int r20, int r21) {
        /*
            Method dump skipped, instructions count: 282
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.ConstraintLayout.n(androidx.constraintlayout.core.widgets.f, int, int, int):void");
    }

    public final void o(androidx.constraintlayout.core.widgets.e eVar, e eVar2, SparseArray sparseArray, int i, int i2) {
        View view = (View) this.a.get(i);
        androidx.constraintlayout.core.widgets.e eVar3 = (androidx.constraintlayout.core.widgets.e) sparseArray.get(i);
        if (eVar3 == null || view == null || !(view.getLayoutParams() instanceof e)) {
            return;
        }
        eVar2.c0 = true;
        if (i2 == 6) {
            e eVar4 = (e) view.getLayoutParams();
            eVar4.c0 = true;
            eVar4.q0.F = true;
        }
        eVar.j(6).b(eVar3.j(i2), eVar2.D, eVar2.C, true);
        eVar.F = true;
        eVar.j(3).j();
        eVar.j(5).j();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        View content;
        int childCount = getChildCount();
        boolean zIsInEditMode = isInEditMode();
        for (int i5 = 0; i5 < childCount; i5++) {
            View childAt = getChildAt(i5);
            e eVar = (e) childAt.getLayoutParams();
            androidx.constraintlayout.core.widgets.e eVar2 = eVar.q0;
            if ((childAt.getVisibility() != 8 || eVar.d0 || eVar.e0 || zIsInEditMode) && !eVar.f0) {
                int iS = eVar2.s();
                int iT = eVar2.t();
                int iR = eVar2.r() + iS;
                int iL = eVar2.l() + iT;
                childAt.layout(iS, iT, iR, iL);
                if ((childAt instanceof s) && (content = ((s) childAt).getContent()) != null) {
                    content.setVisibility(0);
                    content.layout(iS, iT, iR, iL);
                }
            }
        }
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        if (size > 0) {
            for (int i6 = 0; i6 < size; i6++) {
                ((c) arrayList.get(i6)).j();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x02dd  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x02f1  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x030b  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x0351  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x0366  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0384  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x0396  */
    /* JADX WARN: Removed duplicated region for block: B:202:0x03c0  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x03c8  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onMeasure(int r25, int r26) {
        /*
            Method dump skipped, instructions count: 1220
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.ConstraintLayout.onMeasure(int, int):void");
    }

    @Override // android.view.ViewGroup
    public void onViewAdded(View view) {
        super.onViewAdded(view);
        androidx.constraintlayout.core.widgets.e eVarB = b(view);
        if ((view instanceof Guideline) && !(eVarB instanceof androidx.constraintlayout.core.widgets.i)) {
            e eVar = (e) view.getLayoutParams();
            androidx.constraintlayout.core.widgets.i iVar = new androidx.constraintlayout.core.widgets.i();
            eVar.q0 = iVar;
            eVar.d0 = true;
            iVar.W(eVar.V);
        }
        if (view instanceof c) {
            c cVar = (c) view;
            cVar.k();
            ((e) view.getLayoutParams()).e0 = true;
            ArrayList arrayList = this.b;
            if (!arrayList.contains(cVar)) {
                arrayList.add(cVar);
            }
        }
        this.a.put(view.getId(), view);
        this.h = true;
    }

    @Override // android.view.ViewGroup
    public void onViewRemoved(View view) {
        super.onViewRemoved(view);
        this.a.remove(view.getId());
        androidx.constraintlayout.core.widgets.e eVarB = b(view);
        this.c.t0.remove(eVarB);
        eVarB.D();
        this.b.remove(view);
        this.h = true;
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        this.h = true;
        super.requestLayout();
    }

    public void setConstraintSet(o oVar) {
        this.j = oVar;
    }

    @Override // android.view.View
    public void setId(int i) {
        int id = getId();
        SparseArray sparseArray = this.a;
        sparseArray.remove(id);
        super.setId(i);
        sparseArray.put(getId(), this);
    }

    public void setMaxHeight(int i) {
        if (i == this.g) {
            return;
        }
        this.g = i;
        requestLayout();
    }

    public void setMaxWidth(int i) {
        if (i == this.f) {
            return;
        }
        this.f = i;
        requestLayout();
    }

    public void setMinHeight(int i) {
        if (i == this.e) {
            return;
        }
        this.e = i;
        requestLayout();
    }

    public void setMinWidth(int i) {
        if (i == this.d) {
            return;
        }
        this.d = i;
        requestLayout();
    }

    public void setOnConstraintsChanged(r rVar) {
        n0 n0Var = this.k;
        if (n0Var != null) {
            n0Var.getClass();
        }
    }

    public void setOptimizationLevel(int i) {
        this.i = i;
        androidx.constraintlayout.core.widgets.f fVar = this.c;
        fVar.G0 = i;
        androidx.constraintlayout.core.c.q = fVar.c0(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
    }

    @Override // android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return false;
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return new e(layoutParams);
    }

    public ConstraintLayout(@NonNull Context context, AttributeSet attributeSet) throws XmlPullParserException, IOException {
        super(context, attributeSet);
        this.a = new SparseArray();
        this.b = new ArrayList(4);
        this.c = new androidx.constraintlayout.core.widgets.f();
        this.d = 0;
        this.e = 0;
        this.f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.h = true;
        this.i = 257;
        this.j = null;
        this.k = null;
        this.l = -1;
        this.m = new HashMap();
        this.n = new SparseArray();
        this.o = new f(this, this);
        j(attributeSet, 0);
    }

    public ConstraintLayout(Context context, AttributeSet attributeSet, int i) throws XmlPullParserException, IOException {
        super(context, attributeSet, i);
        this.a = new SparseArray();
        this.b = new ArrayList(4);
        this.c = new androidx.constraintlayout.core.widgets.f();
        this.d = 0;
        this.e = 0;
        this.f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.h = true;
        this.i = 257;
        this.j = null;
        this.k = null;
        this.l = -1;
        this.m = new HashMap();
        this.n = new SparseArray();
        this.o = new f(this, this);
        j(attributeSet, i);
    }
}
