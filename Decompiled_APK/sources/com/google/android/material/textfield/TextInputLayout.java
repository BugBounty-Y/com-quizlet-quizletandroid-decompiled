package com.google.android.material.textfield;

import android.R;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Editable;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStructure;
import android.view.ViewTreeObserver;
import android.view.animation.LinearInterpolator;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.K;
import androidx.appcompat.widget.AbstractC0102o0;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.C0112u;
import androidx.compose.ui.text.input.C;
import androidx.core.view.O;
import androidx.core.view.V;
import androidx.customview.view.AbsSavedState;
import androidx.transition.C1404g;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3472i4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3490l4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.material.internal.CheckableImageButton;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class TextInputLayout extends LinearLayout implements ViewTreeObserver.OnGlobalLayoutListener {
    public static final int[][] M1 = {new int[]{R.attr.state_pressed}, new int[0]};
    public ColorStateList A;
    public int A1;
    public ColorStateList B;
    public int B1;
    public boolean C;
    public int C1;
    public CharSequence D;
    public int D1;
    public boolean E;
    public boolean E1;
    public com.google.android.material.shape.g F;
    public final com.google.android.material.internal.b F1;
    public com.google.android.material.shape.g G;
    public boolean G1;
    public StateListDrawable H;
    public boolean H1;
    public boolean I;
    public ValueAnimator I1;
    public com.google.android.material.shape.g J;
    public boolean J1;
    public com.google.android.material.shape.g K;
    public boolean K1;
    public com.google.android.material.shape.j L;
    public boolean L1;
    public boolean M;
    public final int V;
    public int W;
    public final FrameLayout a;
    public final t b;
    public final l c;
    public int c1;
    public EditText d;
    public int d1;
    public CharSequence e;
    public int e1;
    public int f;
    public int f1;
    public int g;
    public int g1;
    public int h;
    public int h1;
    public int i;
    public final Rect i1;
    public final p j;
    public final Rect j1;
    public boolean k;
    public final RectF k1;
    public int l;
    public Typeface l1;
    public boolean m;
    public ColorDrawable m1;
    public w n;
    public int n1;
    public AppCompatTextView o;
    public final LinkedHashSet o1;
    public int p;
    public ColorDrawable p1;
    public int q;
    public int q1;
    public CharSequence r;
    public Drawable r1;
    public boolean s;
    public ColorStateList s1;
    public AppCompatTextView t;
    public ColorStateList t1;
    public ColorStateList u;
    public int u1;
    public int v;
    public int v1;
    public C1404g w;
    public int w1;
    public C1404g x;
    public ColorStateList x1;
    public ColorStateList y;
    public int y1;
    public ColorStateList z;
    public int z1;

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new x();
        public CharSequence c;
        public boolean d;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
            this.d = parcel.readInt() == 1;
        }

        public final String toString() {
            return "TextInputLayout.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " error=" + ((Object) this.c) + "}";
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            TextUtils.writeToParcel(this.c, parcel, i);
            parcel.writeInt(this.d ? 1 : 0);
        }
    }

    public TextInputLayout(@NonNull Context context) {
        this(context, null);
    }

    private Drawable getEditTextBoxBackground() {
        EditText editText = this.d;
        if (!(editText instanceof AutoCompleteTextView) || AbstractC3472i4.a(editText)) {
            return this.F;
        }
        int iB = X3.b(com.quizlet.quizletandroid.R.attr.colorControlHighlight, this.d);
        int i = this.W;
        int[][] iArr = M1;
        if (i != 2) {
            if (i != 1) {
                return null;
            }
            com.google.android.material.shape.g gVar = this.F;
            int i2 = this.h1;
            return new RippleDrawable(new ColorStateList(iArr, new int[]{X3.e(iB, 0.1f, i2), i2}), gVar, gVar);
        }
        Context context = getContext();
        com.google.android.material.shape.g gVar2 = this.F;
        TypedValue typedValueD = AbstractC3436c4.d(context, "TextInputLayout", com.quizlet.quizletandroid.R.attr.colorSurface);
        int i3 = typedValueD.resourceId;
        int color = i3 != 0 ? context.getColor(i3) : typedValueD.data;
        com.google.android.material.shape.g gVar3 = new com.google.android.material.shape.g(gVar2.a.a);
        int iE = X3.e(iB, 0.1f, color);
        gVar3.m(new ColorStateList(iArr, new int[]{iE, 0}));
        gVar3.setTint(color);
        ColorStateList colorStateList = new ColorStateList(iArr, new int[]{iE, color});
        com.google.android.material.shape.g gVar4 = new com.google.android.material.shape.g(gVar2.a.a);
        gVar4.setTint(-1);
        return new LayerDrawable(new Drawable[]{new RippleDrawable(colorStateList, gVar3, gVar4), gVar2});
    }

    private Drawable getOrCreateFilledDropDownMenuBackground() {
        if (this.H == null) {
            StateListDrawable stateListDrawable = new StateListDrawable();
            this.H = stateListDrawable;
            stateListDrawable.addState(new int[]{R.attr.state_above_anchor}, getOrCreateOutlinedDropDownMenuBackground());
            this.H.addState(new int[0], f(false));
        }
        return this.H;
    }

    private Drawable getOrCreateOutlinedDropDownMenuBackground() {
        if (this.G == null) {
            this.G = f(true);
        }
        return this.G;
    }

    public static void k(ViewGroup viewGroup, boolean z) {
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            childAt.setEnabled(z);
            if (childAt instanceof ViewGroup) {
                k((ViewGroup) childAt, z);
            }
        }
    }

    private void setEditText(EditText editText) throws Resources.NotFoundException {
        if (this.d != null) {
            throw new IllegalArgumentException("We already have an EditText, can only have one");
        }
        if (getEndIconMode() != 3 && !(editText instanceof TextInputEditText)) {
            Log.i("TextInputLayout", "EditText added is not a TextInputEditText. Please switch to using that class instead.");
        }
        this.d = editText;
        int i = this.f;
        if (i != -1) {
            setMinEms(i);
        } else {
            setMinWidth(this.h);
        }
        int i2 = this.g;
        if (i2 != -1) {
            setMaxEms(i2);
        } else {
            setMaxWidth(this.i);
        }
        this.I = false;
        i();
        setTextInputAccessibilityDelegate(new v(this));
        Typeface typeface = this.d.getTypeface();
        com.google.android.material.internal.b bVar = this.F1;
        boolean zM = bVar.m(typeface);
        boolean zO = bVar.o(typeface);
        if (zM || zO) {
            bVar.i(false);
        }
        float textSize = this.d.getTextSize();
        if (bVar.l != textSize) {
            bVar.l = textSize;
            bVar.i(false);
        }
        int i3 = Build.VERSION.SDK_INT;
        float letterSpacing = this.d.getLetterSpacing();
        if (bVar.g0 != letterSpacing) {
            bVar.g0 = letterSpacing;
            bVar.i(false);
        }
        int gravity = this.d.getGravity();
        bVar.l((gravity & (-113)) | 48);
        if (bVar.j != gravity) {
            bVar.j = gravity;
            bVar.i(false);
        }
        WeakHashMap weakHashMap = V.a;
        this.D1 = editText.getMinimumHeight();
        this.d.addTextChangedListener(new u(this, editText));
        if (this.s1 == null) {
            this.s1 = this.d.getHintTextColors();
        }
        if (this.C) {
            if (TextUtils.isEmpty(this.D)) {
                CharSequence hint = this.d.getHint();
                this.e = hint;
                setHint(hint);
                this.d.setHint((CharSequence) null);
            }
            this.E = true;
        }
        if (i3 >= 29) {
            p();
        }
        if (this.o != null) {
            n(this.d.getText());
        }
        r();
        this.j.b();
        this.b.bringToFront();
        l lVar = this.c;
        lVar.bringToFront();
        Iterator it2 = this.o1.iterator();
        while (it2.hasNext()) {
            ((k) it2.next()).a(this);
        }
        lVar.m();
        if (!isEnabled()) {
            editText.setEnabled(false);
        }
        u(false, true);
    }

    private void setHintInternal(CharSequence charSequence) {
        if (TextUtils.equals(charSequence, this.D)) {
            return;
        }
        this.D = charSequence;
        com.google.android.material.internal.b bVar = this.F1;
        if (charSequence == null || !TextUtils.equals(bVar.G, charSequence)) {
            bVar.G = charSequence;
            bVar.H = null;
            Bitmap bitmap = bVar.K;
            if (bitmap != null) {
                bitmap.recycle();
                bVar.K = null;
            }
            bVar.i(false);
        }
        if (this.E1) {
            return;
        }
        j();
    }

    private void setPlaceholderTextEnabled(boolean z) {
        if (this.s == z) {
            return;
        }
        if (z) {
            AppCompatTextView appCompatTextView = this.t;
            if (appCompatTextView != null) {
                this.a.addView(appCompatTextView);
                this.t.setVisibility(0);
            }
        } else {
            AppCompatTextView appCompatTextView2 = this.t;
            if (appCompatTextView2 != null) {
                appCompatTextView2.setVisibility(8);
            }
            this.t = null;
        }
        this.s = z;
    }

    public final void a(float f) {
        com.google.android.material.internal.b bVar = this.F1;
        if (bVar.b == f) {
            return;
        }
        if (this.I1 == null) {
            ValueAnimator valueAnimator = new ValueAnimator();
            this.I1 = valueAnimator;
            valueAnimator.setInterpolator(AbstractC3430b4.e(getContext(), com.quizlet.quizletandroid.R.attr.motionEasingEmphasizedInterpolator, com.google.android.material.animation.a.b));
            this.I1.setDuration(AbstractC3430b4.d(getContext(), com.quizlet.quizletandroid.R.attr.motionDurationMedium4, 167));
            this.I1.addUpdateListener(new com.google.android.material.appbar.g(this, 3));
        }
        this.I1.setFloatValues(bVar.b, f);
        this.I1.start();
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) throws Resources.NotFoundException {
        if (!(view instanceof EditText)) {
            super.addView(view, i, layoutParams);
            return;
        }
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(layoutParams);
        layoutParams2.gravity = (layoutParams2.gravity & (-113)) | 16;
        FrameLayout frameLayout = this.a;
        frameLayout.addView(view, layoutParams2);
        frameLayout.setLayoutParams(layoutParams);
        t();
        setEditText((EditText) view);
    }

    public final void b() {
        int i;
        int i2;
        com.google.android.material.shape.g gVar = this.F;
        if (gVar == null) {
            return;
        }
        com.google.android.material.shape.j jVar = gVar.a.a;
        com.google.android.material.shape.j jVar2 = this.L;
        if (jVar != jVar2) {
            gVar.setShapeAppearanceModel(jVar2);
        }
        if (this.W == 2 && (i = this.d1) > -1 && (i2 = this.g1) != 0) {
            com.google.android.material.shape.g gVar2 = this.F;
            gVar2.a.j = i;
            gVar2.invalidateSelf();
            gVar2.r(ColorStateList.valueOf(i2));
        }
        int iB = this.h1;
        if (this.W == 1) {
            iB = androidx.core.graphics.d.b(this.h1, X3.c(getContext(), com.quizlet.quizletandroid.R.attr.colorSurface, 0));
        }
        this.h1 = iB;
        this.F.m(ColorStateList.valueOf(iB));
        com.google.android.material.shape.g gVar3 = this.J;
        if (gVar3 != null && this.K != null) {
            if (this.d1 > -1 && this.g1 != 0) {
                gVar3.m(this.d.isFocused() ? ColorStateList.valueOf(this.u1) : ColorStateList.valueOf(this.g1));
                this.K.m(ColorStateList.valueOf(this.g1));
            }
            invalidate();
        }
        s();
    }

    public final int c() {
        float fE;
        if (!this.C) {
            return 0;
        }
        int i = this.W;
        com.google.android.material.internal.b bVar = this.F1;
        if (i == 0) {
            fE = bVar.e();
        } else {
            if (i != 2) {
                return 0;
            }
            fE = bVar.e() / 2.0f;
        }
        return (int) fE;
    }

    public final C1404g d() {
        C1404g c1404g = new C1404g();
        c1404g.c = AbstractC3430b4.d(getContext(), com.quizlet.quizletandroid.R.attr.motionDurationShort2, 87);
        c1404g.d = AbstractC3430b4.e(getContext(), com.quizlet.quizletandroid.R.attr.motionEasingLinearInterpolator, com.google.android.material.animation.a.a);
        return c1404g;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchProvideAutofillStructure(ViewStructure viewStructure, int i) {
        EditText editText = this.d;
        if (editText == null) {
            super.dispatchProvideAutofillStructure(viewStructure, i);
            return;
        }
        if (this.e != null) {
            boolean z = this.E;
            this.E = false;
            CharSequence hint = editText.getHint();
            this.d.setHint(this.e);
            try {
                super.dispatchProvideAutofillStructure(viewStructure, i);
                return;
            } finally {
                this.d.setHint(hint);
                this.E = z;
            }
        }
        viewStructure.setAutofillId(getAutofillId());
        onProvideAutofillStructure(viewStructure, i);
        onProvideAutofillVirtualStructure(viewStructure, i);
        FrameLayout frameLayout = this.a;
        viewStructure.setChildCount(frameLayout.getChildCount());
        for (int i2 = 0; i2 < frameLayout.getChildCount(); i2++) {
            View childAt = frameLayout.getChildAt(i2);
            ViewStructure viewStructureNewChild = viewStructure.newChild(i2);
            childAt.dispatchProvideAutofillStructure(viewStructureNewChild, i);
            if (childAt == this.d) {
                viewStructureNewChild.setHint(getHint());
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchRestoreInstanceState(SparseArray sparseArray) {
        this.K1 = true;
        super.dispatchRestoreInstanceState(sparseArray);
        this.K1 = false;
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        com.google.android.material.shape.g gVar;
        super.draw(canvas);
        boolean z = this.C;
        com.google.android.material.internal.b bVar = this.F1;
        if (z) {
            bVar.d(canvas);
        }
        if (this.K == null || (gVar = this.J) == null) {
            return;
        }
        gVar.draw(canvas);
        if (this.d.isFocused()) {
            Rect bounds = this.K.getBounds();
            Rect bounds2 = this.J.getBounds();
            float f = bVar.b;
            int iCenterX = bounds2.centerX();
            bounds.left = com.google.android.material.animation.a.c(iCenterX, f, bounds2.left);
            bounds.right = com.google.android.material.animation.a.c(iCenterX, f, bounds2.right);
            this.K.draw(canvas);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002f  */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void drawableStateChanged() throws android.content.res.Resources.NotFoundException {
        /*
            r4 = this;
            boolean r0 = r4.J1
            if (r0 == 0) goto L5
            return
        L5:
            r0 = 1
            r4.J1 = r0
            super.drawableStateChanged()
            int[] r1 = r4.getDrawableState()
            r2 = 0
            com.google.android.material.internal.b r3 = r4.F1
            if (r3 == 0) goto L2f
            r3.R = r1
            android.content.res.ColorStateList r1 = r3.o
            if (r1 == 0) goto L20
            boolean r1 = r1.isStateful()
            if (r1 != 0) goto L2a
        L20:
            android.content.res.ColorStateList r1 = r3.n
            if (r1 == 0) goto L2f
            boolean r1 = r1.isStateful()
            if (r1 == 0) goto L2f
        L2a:
            r3.i(r2)
            r1 = r0
            goto L30
        L2f:
            r1 = r2
        L30:
            android.widget.EditText r3 = r4.d
            if (r3 == 0) goto L47
            java.util.WeakHashMap r3 = androidx.core.view.V.a
            boolean r3 = r4.isLaidOut()
            if (r3 == 0) goto L43
            boolean r3 = r4.isEnabled()
            if (r3 == 0) goto L43
            goto L44
        L43:
            r0 = r2
        L44:
            r4.u(r0, r2)
        L47:
            r4.r()
            r4.x()
            if (r1 == 0) goto L52
            r4.invalidate()
        L52:
            r4.J1 = r2
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.drawableStateChanged():void");
    }

    public final boolean e() {
        return this.C && !TextUtils.isEmpty(this.D) && (this.F instanceof g);
    }

    public final com.google.android.material.shape.g f(boolean z) throws Resources.NotFoundException {
        int i = 0;
        float dimensionPixelOffset = getResources().getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_shape_corner_size_small_component);
        float f = z ? dimensionPixelOffset : DefinitionKt.NO_Float_VALUE;
        EditText editText = this.d;
        float popupElevation = editText instanceof r ? ((r) editText).getPopupElevation() : getResources().getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.m3_comp_outlined_autocomplete_menu_container_elevation);
        int dimensionPixelOffset2 = getResources().getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_exposed_dropdown_menu_popup_vertical_padding);
        com.google.android.material.shape.i iVar = new com.google.android.material.shape.i();
        com.google.android.material.shape.i iVar2 = new com.google.android.material.shape.i();
        com.google.android.material.shape.i iVar3 = new com.google.android.material.shape.i();
        com.google.android.material.shape.i iVar4 = new com.google.android.material.shape.i();
        com.google.android.material.shape.e eVar = new com.google.android.material.shape.e(i);
        com.google.android.material.shape.e eVar2 = new com.google.android.material.shape.e(i);
        com.google.android.material.shape.e eVar3 = new com.google.android.material.shape.e(i);
        com.google.android.material.shape.e eVar4 = new com.google.android.material.shape.e(i);
        com.google.android.material.shape.a aVar = new com.google.android.material.shape.a(f);
        com.google.android.material.shape.a aVar2 = new com.google.android.material.shape.a(f);
        com.google.android.material.shape.a aVar3 = new com.google.android.material.shape.a(dimensionPixelOffset);
        com.google.android.material.shape.a aVar4 = new com.google.android.material.shape.a(dimensionPixelOffset);
        com.google.android.material.shape.j jVar = new com.google.android.material.shape.j();
        jVar.a = iVar;
        jVar.b = iVar2;
        jVar.c = iVar3;
        jVar.d = iVar4;
        jVar.e = aVar;
        jVar.f = aVar2;
        jVar.g = aVar4;
        jVar.h = aVar3;
        jVar.i = eVar;
        jVar.j = eVar2;
        jVar.k = eVar3;
        jVar.l = eVar4;
        EditText editText2 = this.d;
        ColorStateList dropDownBackgroundTintList = editText2 instanceof r ? ((r) editText2).getDropDownBackgroundTintList() : null;
        Context context = getContext();
        if (dropDownBackgroundTintList == null) {
            Paint paint = com.google.android.material.shape.g.x;
            TypedValue typedValueD = AbstractC3436c4.d(context, com.google.android.material.shape.g.class.getSimpleName(), com.quizlet.quizletandroid.R.attr.colorSurface);
            int i2 = typedValueD.resourceId;
            dropDownBackgroundTintList = ColorStateList.valueOf(i2 != 0 ? context.getColor(i2) : typedValueD.data);
        }
        com.google.android.material.shape.g gVar = new com.google.android.material.shape.g();
        gVar.k(context);
        gVar.m(dropDownBackgroundTintList);
        gVar.l(popupElevation);
        gVar.setShapeAppearanceModel(jVar);
        com.google.android.material.shape.f fVar = gVar.a;
        if (fVar.g == null) {
            fVar.g = new Rect();
        }
        gVar.a.g.set(0, dimensionPixelOffset2, 0, dimensionPixelOffset2);
        gVar.invalidateSelf();
        return gVar;
    }

    public final int g(int i, boolean z) {
        return ((z || getPrefixText() == null) ? (!z || getSuffixText() == null) ? this.d.getCompoundPaddingLeft() : this.c.c() : this.b.a()) + i;
    }

    @Override // android.widget.LinearLayout, android.view.View
    public int getBaseline() {
        EditText editText = this.d;
        if (editText == null) {
            return super.getBaseline();
        }
        return c() + getPaddingTop() + editText.getBaseline();
    }

    @NonNull
    public com.google.android.material.shape.g getBoxBackground() {
        int i = this.W;
        if (i == 1 || i == 2) {
            return this.F;
        }
        throw new IllegalStateException();
    }

    public int getBoxBackgroundColor() {
        return this.h1;
    }

    public int getBoxBackgroundMode() {
        return this.W;
    }

    public int getBoxCollapsedPaddingTop() {
        return this.c1;
    }

    public float getBoxCornerRadiusBottomEnd() {
        boolean zK = com.google.android.material.internal.p.k(this);
        RectF rectF = this.k1;
        return zK ? this.L.h.a(rectF) : this.L.g.a(rectF);
    }

    public float getBoxCornerRadiusBottomStart() {
        boolean zK = com.google.android.material.internal.p.k(this);
        RectF rectF = this.k1;
        return zK ? this.L.g.a(rectF) : this.L.h.a(rectF);
    }

    public float getBoxCornerRadiusTopEnd() {
        boolean zK = com.google.android.material.internal.p.k(this);
        RectF rectF = this.k1;
        return zK ? this.L.e.a(rectF) : this.L.f.a(rectF);
    }

    public float getBoxCornerRadiusTopStart() {
        boolean zK = com.google.android.material.internal.p.k(this);
        RectF rectF = this.k1;
        return zK ? this.L.f.a(rectF) : this.L.e.a(rectF);
    }

    public int getBoxStrokeColor() {
        return this.w1;
    }

    public ColorStateList getBoxStrokeErrorColor() {
        return this.x1;
    }

    public int getBoxStrokeWidth() {
        return this.e1;
    }

    public int getBoxStrokeWidthFocused() {
        return this.f1;
    }

    public int getCounterMaxLength() {
        return this.l;
    }

    public CharSequence getCounterOverflowDescription() {
        AppCompatTextView appCompatTextView;
        if (this.k && this.m && (appCompatTextView = this.o) != null) {
            return appCompatTextView.getContentDescription();
        }
        return null;
    }

    public ColorStateList getCounterOverflowTextColor() {
        return this.z;
    }

    public ColorStateList getCounterTextColor() {
        return this.y;
    }

    public ColorStateList getCursorColor() {
        return this.A;
    }

    public ColorStateList getCursorErrorColor() {
        return this.B;
    }

    public ColorStateList getDefaultHintTextColor() {
        return this.s1;
    }

    public EditText getEditText() {
        return this.d;
    }

    public CharSequence getEndIconContentDescription() {
        return this.c.g.getContentDescription();
    }

    public Drawable getEndIconDrawable() {
        return this.c.g.getDrawable();
    }

    public int getEndIconMinSize() {
        return this.c.m;
    }

    public int getEndIconMode() {
        return this.c.i;
    }

    @NonNull
    public ImageView.ScaleType getEndIconScaleType() {
        return this.c.n;
    }

    @NonNull
    public CheckableImageButton getEndIconView() {
        return this.c.g;
    }

    public CharSequence getError() {
        p pVar = this.j;
        if (pVar.q) {
            return pVar.p;
        }
        return null;
    }

    public int getErrorAccessibilityLiveRegion() {
        return this.j.t;
    }

    public CharSequence getErrorContentDescription() {
        return this.j.s;
    }

    public int getErrorCurrentTextColors() {
        AppCompatTextView appCompatTextView = this.j.r;
        if (appCompatTextView != null) {
            return appCompatTextView.getCurrentTextColor();
        }
        return -1;
    }

    public Drawable getErrorIconDrawable() {
        return this.c.c.getDrawable();
    }

    public CharSequence getHelperText() {
        p pVar = this.j;
        if (pVar.x) {
            return pVar.w;
        }
        return null;
    }

    public int getHelperTextCurrentTextColor() {
        AppCompatTextView appCompatTextView = this.j.y;
        if (appCompatTextView != null) {
            return appCompatTextView.getCurrentTextColor();
        }
        return -1;
    }

    public CharSequence getHint() {
        if (this.C) {
            return this.D;
        }
        return null;
    }

    public final float getHintCollapsedTextHeight() {
        return this.F1.e();
    }

    public final int getHintCurrentCollapsedTextColor() {
        com.google.android.material.internal.b bVar = this.F1;
        return bVar.f(bVar.o);
    }

    public ColorStateList getHintTextColor() {
        return this.t1;
    }

    @NonNull
    public w getLengthCounter() {
        return this.n;
    }

    public int getMaxEms() {
        return this.g;
    }

    public int getMaxWidth() {
        return this.i;
    }

    public int getMinEms() {
        return this.f;
    }

    public int getMinWidth() {
        return this.h;
    }

    @Deprecated
    public CharSequence getPasswordVisibilityToggleContentDescription() {
        return this.c.g.getContentDescription();
    }

    @Deprecated
    public Drawable getPasswordVisibilityToggleDrawable() {
        return this.c.g.getDrawable();
    }

    public CharSequence getPlaceholderText() {
        if (this.s) {
            return this.r;
        }
        return null;
    }

    public int getPlaceholderTextAppearance() {
        return this.v;
    }

    public ColorStateList getPlaceholderTextColor() {
        return this.u;
    }

    public CharSequence getPrefixText() {
        return this.b.c;
    }

    public ColorStateList getPrefixTextColor() {
        return this.b.b.getTextColors();
    }

    @NonNull
    public TextView getPrefixTextView() {
        return this.b.b;
    }

    @NonNull
    public com.google.android.material.shape.j getShapeAppearanceModel() {
        return this.L;
    }

    public CharSequence getStartIconContentDescription() {
        return this.b.d.getContentDescription();
    }

    public Drawable getStartIconDrawable() {
        return this.b.d.getDrawable();
    }

    public int getStartIconMinSize() {
        return this.b.g;
    }

    @NonNull
    public ImageView.ScaleType getStartIconScaleType() {
        return this.b.h;
    }

    public CharSequence getSuffixText() {
        return this.c.p;
    }

    public ColorStateList getSuffixTextColor() {
        return this.c.q.getTextColors();
    }

    @NonNull
    public TextView getSuffixTextView() {
        return this.c.q;
    }

    public Typeface getTypeface() {
        return this.l1;
    }

    public final int h(int i, boolean z) {
        return i - ((z || getSuffixText() == null) ? (!z || getPrefixText() == null) ? this.d.getCompoundPaddingRight() : this.b.a() : this.c.c());
    }

    public final void i() throws Resources.NotFoundException {
        int i = this.W;
        if (i == 0) {
            this.F = null;
            this.J = null;
            this.K = null;
        } else if (i == 1) {
            this.F = new com.google.android.material.shape.g(this.L);
            this.J = new com.google.android.material.shape.g();
            this.K = new com.google.android.material.shape.g();
        } else {
            if (i != 2) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.r(new StringBuilder(), this.W, " is illegal; only @BoxBackgroundMode constants are supported."));
            }
            if (!this.C || (this.F instanceof g)) {
                this.F = new com.google.android.material.shape.g(this.L);
            } else {
                com.google.android.material.shape.j jVar = this.L;
                int i2 = g.z;
                if (jVar == null) {
                    jVar = new com.google.android.material.shape.j();
                }
                f fVar = new f(jVar, new RectF());
                g gVar = new g(fVar);
                gVar.y = fVar;
                this.F = gVar;
            }
            this.J = null;
            this.K = null;
        }
        s();
        x();
        if (this.W == 1) {
            if (getContext().getResources().getConfiguration().fontScale >= 2.0f) {
                this.c1 = getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_font_2_0_box_collapsed_padding_top);
            } else if (AbstractC3442d4.e(getContext())) {
                this.c1 = getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_font_1_3_box_collapsed_padding_top);
            }
        }
        if (this.d != null && this.W == 1) {
            if (getContext().getResources().getConfiguration().fontScale >= 2.0f) {
                EditText editText = this.d;
                WeakHashMap weakHashMap = V.a;
                editText.setPaddingRelative(editText.getPaddingStart(), getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_filled_edittext_font_2_0_padding_top), this.d.getPaddingEnd(), getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_filled_edittext_font_2_0_padding_bottom));
            } else if (AbstractC3442d4.e(getContext())) {
                EditText editText2 = this.d;
                WeakHashMap weakHashMap2 = V.a;
                editText2.setPaddingRelative(editText2.getPaddingStart(), getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_filled_edittext_font_1_3_padding_top), this.d.getPaddingEnd(), getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.material_filled_edittext_font_1_3_padding_bottom));
            }
        }
        if (this.W != 0) {
            t();
        }
        EditText editText3 = this.d;
        if (editText3 instanceof AutoCompleteTextView) {
            AutoCompleteTextView autoCompleteTextView = (AutoCompleteTextView) editText3;
            if (autoCompleteTextView.getDropDownBackground() == null) {
                int i3 = this.W;
                if (i3 == 2) {
                    autoCompleteTextView.setDropDownBackgroundDrawable(getOrCreateOutlinedDropDownMenuBackground());
                } else if (i3 == 1) {
                    autoCompleteTextView.setDropDownBackgroundDrawable(getOrCreateFilledDropDownMenuBackground());
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x008d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j() {
        /*
            Method dump skipped, instructions count: 241
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.j():void");
    }

    public final void l(AppCompatTextView appCompatTextView, int i) {
        try {
            appCompatTextView.setTextAppearance(i);
            if (appCompatTextView.getTextColors().getDefaultColor() != -65281) {
                return;
            }
        } catch (Exception unused) {
        }
        appCompatTextView.setTextAppearance(com.quizlet.quizletandroid.R.style.TextAppearance_AppCompat_Caption);
        appCompatTextView.setTextColor(getContext().getColor(com.quizlet.quizletandroid.R.color.design_error));
    }

    public final boolean m() {
        p pVar = this.j;
        return (pVar.o != 1 || pVar.r == null || TextUtils.isEmpty(pVar.p)) ? false : true;
    }

    public final void n(Editable editable) throws Resources.NotFoundException {
        ((com.facebook.appevents.k) this.n).getClass();
        int length = editable != null ? editable.length() : 0;
        boolean z = this.m;
        int i = this.l;
        String string = null;
        if (i == -1) {
            this.o.setText(String.valueOf(length));
            this.o.setContentDescription(null);
            this.m = false;
        } else {
            this.m = length > i;
            Context context = getContext();
            this.o.setContentDescription(context.getString(this.m ? com.quizlet.quizletandroid.R.string.character_counter_overflowed_content_description : com.quizlet.quizletandroid.R.string.character_counter_content_description, Integer.valueOf(length), Integer.valueOf(this.l)));
            if (z != this.m) {
                o();
            }
            androidx.core.text.b bVarC = androidx.core.text.b.c();
            AppCompatTextView appCompatTextView = this.o;
            String string2 = getContext().getString(com.quizlet.quizletandroid.R.string.character_counter_pattern, Integer.valueOf(length), Integer.valueOf(this.l));
            if (string2 == null) {
                bVarC.getClass();
            } else {
                bVarC.getClass();
                K k = androidx.core.text.f.a;
                string = bVarC.d(string2).toString();
            }
            appCompatTextView.setText(string);
        }
        if (this.d == null || z == this.m) {
            return;
        }
        u(false, false);
        x();
        r();
    }

    public final void o() {
        ColorStateList colorStateList;
        ColorStateList colorStateList2;
        AppCompatTextView appCompatTextView = this.o;
        if (appCompatTextView != null) {
            l(appCompatTextView, this.m ? this.p : this.q);
            if (!this.m && (colorStateList2 = this.y) != null) {
                this.o.setTextColor(colorStateList2);
            }
            if (!this.m || (colorStateList = this.z) == null) {
                return;
            }
            this.o.setTextColor(colorStateList);
        }
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.F1.h(configuration);
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        int iMax;
        l lVar = this.c;
        lVar.getViewTreeObserver().removeOnGlobalLayoutListener(this);
        boolean z = false;
        this.L1 = false;
        if (this.d != null && this.d.getMeasuredHeight() < (iMax = Math.max(lVar.getMeasuredHeight(), this.b.getMeasuredHeight()))) {
            this.d.setMinimumHeight(iMax);
            z = true;
        }
        boolean zQ = q();
        if (z || zQ) {
            this.d.post(new C(this, 27));
        }
    }

    @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        EditText editText = this.d;
        if (editText != null) {
            Rect rect = this.i1;
            com.google.android.material.internal.c.a(this, editText, rect);
            com.google.android.material.shape.g gVar = this.J;
            if (gVar != null) {
                int i5 = rect.bottom;
                gVar.setBounds(rect.left, i5 - this.e1, rect.right, i5);
            }
            com.google.android.material.shape.g gVar2 = this.K;
            if (gVar2 != null) {
                int i6 = rect.bottom;
                gVar2.setBounds(rect.left, i6 - this.f1, rect.right, i6);
            }
            if (this.C) {
                float textSize = this.d.getTextSize();
                com.google.android.material.internal.b bVar = this.F1;
                if (bVar.l != textSize) {
                    bVar.l = textSize;
                    bVar.i(false);
                }
                int gravity = this.d.getGravity();
                bVar.l((gravity & (-113)) | 48);
                if (bVar.j != gravity) {
                    bVar.j = gravity;
                    bVar.i(false);
                }
                if (this.d == null) {
                    throw new IllegalStateException();
                }
                boolean zK = com.google.android.material.internal.p.k(this);
                int i7 = rect.bottom;
                Rect rect2 = this.j1;
                rect2.bottom = i7;
                int i8 = this.W;
                if (i8 == 1) {
                    rect2.left = g(rect.left, zK);
                    rect2.top = rect.top + this.c1;
                    rect2.right = h(rect.right, zK);
                } else if (i8 != 2) {
                    rect2.left = g(rect.left, zK);
                    rect2.top = getPaddingTop();
                    rect2.right = h(rect.right, zK);
                } else {
                    rect2.left = this.d.getPaddingLeft() + rect.left;
                    rect2.top = rect.top - c();
                    rect2.right = rect.right - this.d.getPaddingRight();
                }
                int i9 = rect2.left;
                int i10 = rect2.top;
                int i11 = rect2.right;
                int i12 = rect2.bottom;
                Rect rect3 = bVar.h;
                if (rect3.left != i9 || rect3.top != i10 || rect3.right != i11 || rect3.bottom != i12) {
                    rect3.set(i9, i10, i11, i12);
                    bVar.S = true;
                }
                if (this.d == null) {
                    throw new IllegalStateException();
                }
                TextPaint textPaint = bVar.U;
                textPaint.setTextSize(bVar.l);
                textPaint.setTypeface(bVar.z);
                textPaint.setLetterSpacing(bVar.g0);
                float f = -textPaint.ascent();
                rect2.left = this.d.getCompoundPaddingLeft() + rect.left;
                rect2.top = (this.W != 1 || this.d.getMinLines() > 1) ? rect.top + this.d.getCompoundPaddingTop() : (int) (rect.centerY() - (f / 2.0f));
                rect2.right = rect.right - this.d.getCompoundPaddingRight();
                int compoundPaddingBottom = (this.W != 1 || this.d.getMinLines() > 1) ? rect.bottom - this.d.getCompoundPaddingBottom() : (int) (rect2.top + f);
                rect2.bottom = compoundPaddingBottom;
                int i13 = rect2.left;
                int i14 = rect2.top;
                int i15 = rect2.right;
                Rect rect4 = bVar.g;
                if (rect4.left != i13 || rect4.top != i14 || rect4.right != i15 || rect4.bottom != compoundPaddingBottom) {
                    rect4.set(i13, i14, i15, compoundPaddingBottom);
                    bVar.S = true;
                }
                bVar.i(false);
                if (!e() || this.E1) {
                    return;
                }
                j();
            }
        }
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onMeasure(int i, int i2) throws Resources.NotFoundException {
        EditText editText;
        super.onMeasure(i, i2);
        boolean z = this.L1;
        l lVar = this.c;
        if (!z) {
            lVar.getViewTreeObserver().addOnGlobalLayoutListener(this);
            this.L1 = true;
        }
        if (this.t != null && (editText = this.d) != null) {
            this.t.setGravity(editText.getGravity());
            this.t.setPadding(this.d.getCompoundPaddingLeft(), this.d.getCompoundPaddingTop(), this.d.getCompoundPaddingRight(), this.d.getCompoundPaddingBottom());
        }
        lVar.m();
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) throws Resources.NotFoundException {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        setError(savedState.c);
        if (savedState.d) {
            post(new com.google.android.gms.common.api.internal.w(this, 13));
        }
        requestLayout();
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onRtlPropertiesChanged(int i) {
        super.onRtlPropertiesChanged(i);
        boolean z = i == 1;
        if (z != this.M) {
            com.google.android.material.shape.c cVar = this.L.e;
            RectF rectF = this.k1;
            float fA = cVar.a(rectF);
            float fA2 = this.L.f.a(rectF);
            float fA3 = this.L.h.a(rectF);
            float fA4 = this.L.g.a(rectF);
            com.google.android.material.shape.j jVar = this.L;
            AbstractC3460g4 abstractC3460g4 = jVar.a;
            AbstractC3460g4 abstractC3460g42 = jVar.b;
            AbstractC3460g4 abstractC3460g43 = jVar.d;
            AbstractC3460g4 abstractC3460g44 = jVar.c;
            com.google.android.material.shape.e eVar = new com.google.android.material.shape.e(0);
            com.google.android.material.shape.e eVar2 = new com.google.android.material.shape.e(0);
            com.google.android.material.shape.e eVar3 = new com.google.android.material.shape.e(0);
            com.google.android.material.shape.e eVar4 = new com.google.android.material.shape.e(0);
            G4.b(abstractC3460g42);
            G4.b(abstractC3460g4);
            G4.b(abstractC3460g44);
            G4.b(abstractC3460g43);
            com.google.android.material.shape.a aVar = new com.google.android.material.shape.a(fA2);
            com.google.android.material.shape.a aVar2 = new com.google.android.material.shape.a(fA);
            com.google.android.material.shape.a aVar3 = new com.google.android.material.shape.a(fA4);
            com.google.android.material.shape.a aVar4 = new com.google.android.material.shape.a(fA3);
            com.google.android.material.shape.j jVar2 = new com.google.android.material.shape.j();
            jVar2.a = abstractC3460g42;
            jVar2.b = abstractC3460g4;
            jVar2.c = abstractC3460g43;
            jVar2.d = abstractC3460g44;
            jVar2.e = aVar;
            jVar2.f = aVar2;
            jVar2.g = aVar4;
            jVar2.h = aVar3;
            jVar2.i = eVar;
            jVar2.j = eVar2;
            jVar2.k = eVar3;
            jVar2.l = eVar4;
            this.M = z;
            setShapeAppearanceModel(jVar2);
        }
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        if (m()) {
            savedState.c = getError();
        }
        l lVar = this.c;
        savedState.d = lVar.i != 0 && lVar.g.d;
        return savedState;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0025  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p() {
        /*
            r3 = this;
            android.content.res.ColorStateList r0 = r3.A
            if (r0 == 0) goto L5
            goto L26
        L5:
            android.content.Context r0 = r3.getContext()
            r1 = 2130969183(0x7f04025f, float:1.754704E38)
            android.util.TypedValue r1 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4.b(r0, r1)
            if (r1 != 0) goto L13
            goto L25
        L13:
            int r2 = r1.resourceId
            if (r2 == 0) goto L1c
            android.content.res.ColorStateList r0 = androidx.core.content.c.c(r0, r2)
            goto L26
        L1c:
            int r0 = r1.data
            if (r0 == 0) goto L25
            android.content.res.ColorStateList r0 = android.content.res.ColorStateList.valueOf(r0)
            goto L26
        L25:
            r0 = 0
        L26:
            android.widget.EditText r1 = r3.d
            if (r1 == 0) goto L51
            android.graphics.drawable.Drawable r1 = com.bumptech.glide.load.model.stream.g.g(r1)
            if (r1 != 0) goto L31
            goto L51
        L31:
            android.widget.EditText r1 = r3.d
            android.graphics.drawable.Drawable r1 = com.bumptech.glide.load.model.stream.g.g(r1)
            android.graphics.drawable.Drawable r1 = r1.mutate()
            boolean r2 = r3.m()
            if (r2 != 0) goto L49
            androidx.appcompat.widget.AppCompatTextView r2 = r3.o
            if (r2 == 0) goto L4e
            boolean r2 = r3.m
            if (r2 == 0) goto L4e
        L49:
            android.content.res.ColorStateList r2 = r3.B
            if (r2 == 0) goto L4e
            r0 = r2
        L4e:
            r1.setTintList(r0)
        L51:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.p():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean q() {
        /*
            Method dump skipped, instructions count: 304
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.q():boolean");
    }

    public final void r() {
        Drawable background;
        AppCompatTextView appCompatTextView;
        EditText editText = this.d;
        if (editText == null || this.W != 0 || (background = editText.getBackground()) == null) {
            return;
        }
        int[] iArr = AbstractC0102o0.a;
        Drawable drawableMutate = background.mutate();
        if (m()) {
            drawableMutate.setColorFilter(C0112u.c(getErrorCurrentTextColors(), PorterDuff.Mode.SRC_IN));
        } else if (this.m && (appCompatTextView = this.o) != null) {
            drawableMutate.setColorFilter(C0112u.c(appCompatTextView.getCurrentTextColor(), PorterDuff.Mode.SRC_IN));
        } else {
            drawableMutate.clearColorFilter();
            this.d.refreshDrawableState();
        }
    }

    public final void s() {
        EditText editText = this.d;
        if (editText == null || this.F == null) {
            return;
        }
        if ((this.I || editText.getBackground() == null) && this.W != 0) {
            Drawable editTextBoxBackground = getEditTextBoxBackground();
            EditText editText2 = this.d;
            WeakHashMap weakHashMap = V.a;
            editText2.setBackground(editTextBoxBackground);
            this.I = true;
        }
    }

    public void setBoxBackgroundColor(int i) {
        if (this.h1 != i) {
            this.h1 = i;
            this.y1 = i;
            this.A1 = i;
            this.B1 = i;
            b();
        }
    }

    public void setBoxBackgroundColorResource(int i) {
        setBoxBackgroundColor(getContext().getColor(i));
    }

    public void setBoxBackgroundColorStateList(@NonNull ColorStateList colorStateList) {
        int defaultColor = colorStateList.getDefaultColor();
        this.y1 = defaultColor;
        this.h1 = defaultColor;
        this.z1 = colorStateList.getColorForState(new int[]{-16842910}, -1);
        this.A1 = colorStateList.getColorForState(new int[]{R.attr.state_focused, R.attr.state_enabled}, -1);
        this.B1 = colorStateList.getColorForState(new int[]{R.attr.state_hovered, R.attr.state_enabled}, -1);
        b();
    }

    public void setBoxBackgroundMode(int i) throws Resources.NotFoundException {
        if (i == this.W) {
            return;
        }
        this.W = i;
        if (this.d != null) {
            i();
        }
    }

    public void setBoxCollapsedPaddingTop(int i) {
        this.c1 = i;
    }

    public void setBoxCornerFamily(int i) {
        G4 g4F = this.L.f();
        com.google.android.material.shape.c cVar = this.L.e;
        AbstractC3460g4 abstractC3460g4A = AbstractC3466h4.a(i);
        g4F.a = abstractC3460g4A;
        G4.b(abstractC3460g4A);
        g4F.e = cVar;
        com.google.android.material.shape.c cVar2 = this.L.f;
        AbstractC3460g4 abstractC3460g4A2 = AbstractC3466h4.a(i);
        g4F.b = abstractC3460g4A2;
        G4.b(abstractC3460g4A2);
        g4F.f = cVar2;
        com.google.android.material.shape.c cVar3 = this.L.h;
        AbstractC3460g4 abstractC3460g4A3 = AbstractC3466h4.a(i);
        g4F.d = abstractC3460g4A3;
        G4.b(abstractC3460g4A3);
        g4F.h = cVar3;
        com.google.android.material.shape.c cVar4 = this.L.g;
        AbstractC3460g4 abstractC3460g4A4 = AbstractC3466h4.a(i);
        g4F.c = abstractC3460g4A4;
        G4.b(abstractC3460g4A4);
        g4F.g = cVar4;
        this.L = g4F.a();
        b();
    }

    public void setBoxStrokeColor(int i) throws Resources.NotFoundException {
        if (this.w1 != i) {
            this.w1 = i;
            x();
        }
    }

    public void setBoxStrokeColorStateList(@NonNull ColorStateList colorStateList) throws Resources.NotFoundException {
        if (colorStateList.isStateful()) {
            this.u1 = colorStateList.getDefaultColor();
            this.C1 = colorStateList.getColorForState(new int[]{-16842910}, -1);
            this.v1 = colorStateList.getColorForState(new int[]{R.attr.state_hovered, R.attr.state_enabled}, -1);
            this.w1 = colorStateList.getColorForState(new int[]{R.attr.state_focused, R.attr.state_enabled}, -1);
        } else if (this.w1 != colorStateList.getDefaultColor()) {
            this.w1 = colorStateList.getDefaultColor();
        }
        x();
    }

    public void setBoxStrokeErrorColor(ColorStateList colorStateList) throws Resources.NotFoundException {
        if (this.x1 != colorStateList) {
            this.x1 = colorStateList;
            x();
        }
    }

    public void setBoxStrokeWidth(int i) throws Resources.NotFoundException {
        this.e1 = i;
        x();
    }

    public void setBoxStrokeWidthFocused(int i) throws Resources.NotFoundException {
        this.f1 = i;
        x();
    }

    public void setBoxStrokeWidthFocusedResource(int i) throws Resources.NotFoundException {
        setBoxStrokeWidthFocused(getResources().getDimensionPixelSize(i));
    }

    public void setBoxStrokeWidthResource(int i) throws Resources.NotFoundException {
        setBoxStrokeWidth(getResources().getDimensionPixelSize(i));
    }

    public void setCounterEnabled(boolean z) throws Resources.NotFoundException {
        if (this.k != z) {
            p pVar = this.j;
            if (z) {
                AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
                this.o = appCompatTextView;
                appCompatTextView.setId(com.quizlet.quizletandroid.R.id.textinput_counter);
                Typeface typeface = this.l1;
                if (typeface != null) {
                    this.o.setTypeface(typeface);
                }
                this.o.setMaxLines(1);
                pVar.a(this.o, 2);
                ((ViewGroup.MarginLayoutParams) this.o.getLayoutParams()).setMarginStart(getResources().getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_textinput_counter_margin_start));
                o();
                if (this.o != null) {
                    EditText editText = this.d;
                    n(editText != null ? editText.getText() : null);
                }
            } else {
                pVar.g(this.o, 2);
                this.o = null;
            }
            this.k = z;
        }
    }

    public void setCounterMaxLength(int i) throws Resources.NotFoundException {
        if (this.l != i) {
            if (i > 0) {
                this.l = i;
            } else {
                this.l = -1;
            }
            if (!this.k || this.o == null) {
                return;
            }
            EditText editText = this.d;
            n(editText == null ? null : editText.getText());
        }
    }

    public void setCounterOverflowTextAppearance(int i) {
        if (this.p != i) {
            this.p = i;
            o();
        }
    }

    public void setCounterOverflowTextColor(ColorStateList colorStateList) {
        if (this.z != colorStateList) {
            this.z = colorStateList;
            o();
        }
    }

    public void setCounterTextAppearance(int i) {
        if (this.q != i) {
            this.q = i;
            o();
        }
    }

    public void setCounterTextColor(ColorStateList colorStateList) {
        if (this.y != colorStateList) {
            this.y = colorStateList;
            o();
        }
    }

    public void setCursorColor(ColorStateList colorStateList) {
        if (this.A != colorStateList) {
            this.A = colorStateList;
            p();
        }
    }

    public void setCursorErrorColor(ColorStateList colorStateList) {
        if (this.B != colorStateList) {
            this.B = colorStateList;
            if (m() || (this.o != null && this.m)) {
                p();
            }
        }
    }

    public void setDefaultHintTextColor(ColorStateList colorStateList) {
        this.s1 = colorStateList;
        this.t1 = colorStateList;
        if (this.d != null) {
            u(false, false);
        }
    }

    @Override // android.view.View
    public void setEnabled(boolean z) {
        k(this, z);
        super.setEnabled(z);
    }

    public void setEndIconActivated(boolean z) {
        this.c.g.setActivated(z);
    }

    public void setEndIconCheckable(boolean z) {
        this.c.g.setCheckable(z);
    }

    public void setEndIconContentDescription(int i) {
        l lVar = this.c;
        CharSequence text = i != 0 ? lVar.getResources().getText(i) : null;
        CheckableImageButton checkableImageButton = lVar.g;
        if (checkableImageButton.getContentDescription() != text) {
            checkableImageButton.setContentDescription(text);
        }
    }

    public void setEndIconDrawable(int i) {
        l lVar = this.c;
        Drawable drawableF = i != 0 ? com.facebook.appevents.g.f(lVar.getContext(), i) : null;
        CheckableImageButton checkableImageButton = lVar.g;
        checkableImageButton.setImageDrawable(drawableF);
        if (drawableF != null) {
            ColorStateList colorStateList = lVar.k;
            PorterDuff.Mode mode = lVar.l;
            TextInputLayout textInputLayout = lVar.a;
            AbstractC3490l4.a(textInputLayout, checkableImageButton, colorStateList, mode);
            AbstractC3490l4.c(textInputLayout, checkableImageButton, lVar.k);
        }
    }

    public void setEndIconMinSize(int i) {
        l lVar = this.c;
        if (i < 0) {
            lVar.getClass();
            throw new IllegalArgumentException("endIconSize cannot be less than 0");
        }
        if (i != lVar.m) {
            lVar.m = i;
            CheckableImageButton checkableImageButton = lVar.g;
            checkableImageButton.setMinimumWidth(i);
            checkableImageButton.setMinimumHeight(i);
            CheckableImageButton checkableImageButton2 = lVar.c;
            checkableImageButton2.setMinimumWidth(i);
            checkableImageButton2.setMinimumHeight(i);
        }
    }

    public void setEndIconMode(int i) throws Resources.NotFoundException {
        this.c.g(i);
    }

    public void setEndIconOnClickListener(View.OnClickListener onClickListener) {
        l lVar = this.c;
        View.OnLongClickListener onLongClickListener = lVar.o;
        CheckableImageButton checkableImageButton = lVar.g;
        checkableImageButton.setOnClickListener(onClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setEndIconOnLongClickListener(View.OnLongClickListener onLongClickListener) {
        l lVar = this.c;
        lVar.o = onLongClickListener;
        CheckableImageButton checkableImageButton = lVar.g;
        checkableImageButton.setOnLongClickListener(onLongClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setEndIconScaleType(@NonNull ImageView.ScaleType scaleType) {
        l lVar = this.c;
        lVar.n = scaleType;
        lVar.g.setScaleType(scaleType);
        lVar.c.setScaleType(scaleType);
    }

    public void setEndIconTintList(ColorStateList colorStateList) {
        l lVar = this.c;
        if (lVar.k != colorStateList) {
            lVar.k = colorStateList;
            AbstractC3490l4.a(lVar.a, lVar.g, colorStateList, lVar.l);
        }
    }

    public void setEndIconTintMode(PorterDuff.Mode mode) {
        l lVar = this.c;
        if (lVar.l != mode) {
            lVar.l = mode;
            AbstractC3490l4.a(lVar.a, lVar.g, lVar.k, mode);
        }
    }

    public void setEndIconVisible(boolean z) throws Resources.NotFoundException {
        this.c.h(z);
    }

    public void setError(CharSequence charSequence) throws Resources.NotFoundException {
        p pVar = this.j;
        if (!pVar.q) {
            if (TextUtils.isEmpty(charSequence)) {
                return;
            } else {
                setErrorEnabled(true);
            }
        }
        if (TextUtils.isEmpty(charSequence)) {
            pVar.f();
            return;
        }
        pVar.c();
        pVar.p = charSequence;
        pVar.r.setText(charSequence);
        int i = pVar.n;
        if (i != 1) {
            pVar.o = 1;
        }
        pVar.i(i, pVar.o, pVar.h(pVar.r, charSequence));
    }

    public void setErrorAccessibilityLiveRegion(int i) {
        p pVar = this.j;
        pVar.t = i;
        AppCompatTextView appCompatTextView = pVar.r;
        if (appCompatTextView != null) {
            WeakHashMap weakHashMap = V.a;
            appCompatTextView.setAccessibilityLiveRegion(i);
        }
    }

    public void setErrorContentDescription(CharSequence charSequence) {
        p pVar = this.j;
        pVar.s = charSequence;
        AppCompatTextView appCompatTextView = pVar.r;
        if (appCompatTextView != null) {
            appCompatTextView.setContentDescription(charSequence);
        }
    }

    public void setErrorEnabled(boolean z) throws Resources.NotFoundException {
        p pVar = this.j;
        if (pVar.q == z) {
            return;
        }
        pVar.c();
        TextInputLayout textInputLayout = pVar.h;
        if (z) {
            AppCompatTextView appCompatTextView = new AppCompatTextView(pVar.g);
            pVar.r = appCompatTextView;
            appCompatTextView.setId(com.quizlet.quizletandroid.R.id.textinput_error);
            pVar.r.setTextAlignment(5);
            Typeface typeface = pVar.B;
            if (typeface != null) {
                pVar.r.setTypeface(typeface);
            }
            int i = pVar.u;
            pVar.u = i;
            AppCompatTextView appCompatTextView2 = pVar.r;
            if (appCompatTextView2 != null) {
                textInputLayout.l(appCompatTextView2, i);
            }
            ColorStateList colorStateList = pVar.v;
            pVar.v = colorStateList;
            AppCompatTextView appCompatTextView3 = pVar.r;
            if (appCompatTextView3 != null && colorStateList != null) {
                appCompatTextView3.setTextColor(colorStateList);
            }
            CharSequence charSequence = pVar.s;
            pVar.s = charSequence;
            AppCompatTextView appCompatTextView4 = pVar.r;
            if (appCompatTextView4 != null) {
                appCompatTextView4.setContentDescription(charSequence);
            }
            int i2 = pVar.t;
            pVar.t = i2;
            AppCompatTextView appCompatTextView5 = pVar.r;
            if (appCompatTextView5 != null) {
                WeakHashMap weakHashMap = V.a;
                appCompatTextView5.setAccessibilityLiveRegion(i2);
            }
            pVar.r.setVisibility(4);
            pVar.a(pVar.r, 0);
        } else {
            pVar.f();
            pVar.g(pVar.r, 0);
            pVar.r = null;
            textInputLayout.r();
            textInputLayout.x();
        }
        pVar.q = z;
    }

    public void setErrorIconDrawable(int i) throws Resources.NotFoundException {
        l lVar = this.c;
        lVar.i(i != 0 ? com.facebook.appevents.g.f(lVar.getContext(), i) : null);
        AbstractC3490l4.c(lVar.a, lVar.c, lVar.d);
    }

    public void setErrorIconOnClickListener(View.OnClickListener onClickListener) {
        l lVar = this.c;
        CheckableImageButton checkableImageButton = lVar.c;
        View.OnLongClickListener onLongClickListener = lVar.f;
        checkableImageButton.setOnClickListener(onClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setErrorIconOnLongClickListener(View.OnLongClickListener onLongClickListener) {
        l lVar = this.c;
        lVar.f = onLongClickListener;
        CheckableImageButton checkableImageButton = lVar.c;
        checkableImageButton.setOnLongClickListener(onLongClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setErrorIconTintList(ColorStateList colorStateList) {
        l lVar = this.c;
        if (lVar.d != colorStateList) {
            lVar.d = colorStateList;
            AbstractC3490l4.a(lVar.a, lVar.c, colorStateList, lVar.e);
        }
    }

    public void setErrorIconTintMode(PorterDuff.Mode mode) {
        l lVar = this.c;
        if (lVar.e != mode) {
            lVar.e = mode;
            AbstractC3490l4.a(lVar.a, lVar.c, lVar.d, mode);
        }
    }

    public void setErrorTextAppearance(int i) {
        p pVar = this.j;
        pVar.u = i;
        AppCompatTextView appCompatTextView = pVar.r;
        if (appCompatTextView != null) {
            pVar.h.l(appCompatTextView, i);
        }
    }

    public void setErrorTextColor(ColorStateList colorStateList) {
        p pVar = this.j;
        pVar.v = colorStateList;
        AppCompatTextView appCompatTextView = pVar.r;
        if (appCompatTextView == null || colorStateList == null) {
            return;
        }
        appCompatTextView.setTextColor(colorStateList);
    }

    public void setExpandedHintEnabled(boolean z) {
        if (this.G1 != z) {
            this.G1 = z;
            u(false, false);
        }
    }

    public void setHelperText(CharSequence charSequence) throws Resources.NotFoundException {
        boolean zIsEmpty = TextUtils.isEmpty(charSequence);
        p pVar = this.j;
        if (zIsEmpty) {
            if (pVar.x) {
                setHelperTextEnabled(false);
                return;
            }
            return;
        }
        if (!pVar.x) {
            setHelperTextEnabled(true);
        }
        pVar.c();
        pVar.w = charSequence;
        pVar.y.setText(charSequence);
        int i = pVar.n;
        if (i != 2) {
            pVar.o = 2;
        }
        pVar.i(i, pVar.o, pVar.h(pVar.y, charSequence));
    }

    public void setHelperTextColor(ColorStateList colorStateList) {
        p pVar = this.j;
        pVar.A = colorStateList;
        AppCompatTextView appCompatTextView = pVar.y;
        if (appCompatTextView == null || colorStateList == null) {
            return;
        }
        appCompatTextView.setTextColor(colorStateList);
    }

    public void setHelperTextEnabled(boolean z) throws Resources.NotFoundException {
        int i = 0;
        p pVar = this.j;
        if (pVar.x == z) {
            return;
        }
        pVar.c();
        if (z) {
            AppCompatTextView appCompatTextView = new AppCompatTextView(pVar.g);
            pVar.y = appCompatTextView;
            appCompatTextView.setId(com.quizlet.quizletandroid.R.id.textinput_helper_text);
            pVar.y.setTextAlignment(5);
            Typeface typeface = pVar.B;
            if (typeface != null) {
                pVar.y.setTypeface(typeface);
            }
            pVar.y.setVisibility(4);
            AppCompatTextView appCompatTextView2 = pVar.y;
            WeakHashMap weakHashMap = V.a;
            appCompatTextView2.setAccessibilityLiveRegion(1);
            int i2 = pVar.z;
            pVar.z = i2;
            AppCompatTextView appCompatTextView3 = pVar.y;
            if (appCompatTextView3 != null) {
                appCompatTextView3.setTextAppearance(i2);
            }
            ColorStateList colorStateList = pVar.A;
            pVar.A = colorStateList;
            AppCompatTextView appCompatTextView4 = pVar.y;
            if (appCompatTextView4 != null && colorStateList != null) {
                appCompatTextView4.setTextColor(colorStateList);
            }
            pVar.a(pVar.y, 1);
            pVar.y.setAccessibilityDelegate(new o(pVar, i));
        } else {
            pVar.c();
            int i3 = pVar.n;
            if (i3 == 2) {
                pVar.o = 0;
            }
            pVar.i(i3, pVar.o, pVar.h(pVar.y, ""));
            pVar.g(pVar.y, 1);
            pVar.y = null;
            TextInputLayout textInputLayout = pVar.h;
            textInputLayout.r();
            textInputLayout.x();
        }
        pVar.x = z;
    }

    public void setHelperTextTextAppearance(int i) {
        p pVar = this.j;
        pVar.z = i;
        AppCompatTextView appCompatTextView = pVar.y;
        if (appCompatTextView != null) {
            appCompatTextView.setTextAppearance(i);
        }
    }

    public void setHint(CharSequence charSequence) {
        if (this.C) {
            setHintInternal(charSequence);
            sendAccessibilityEvent(2048);
        }
    }

    public void setHintAnimationEnabled(boolean z) {
        this.H1 = z;
    }

    public void setHintEnabled(boolean z) {
        if (z != this.C) {
            this.C = z;
            if (z) {
                CharSequence hint = this.d.getHint();
                if (!TextUtils.isEmpty(hint)) {
                    if (TextUtils.isEmpty(this.D)) {
                        setHint(hint);
                    }
                    this.d.setHint((CharSequence) null);
                }
                this.E = true;
            } else {
                this.E = false;
                if (!TextUtils.isEmpty(this.D) && TextUtils.isEmpty(this.d.getHint())) {
                    this.d.setHint(this.D);
                }
                setHintInternal(null);
            }
            if (this.d != null) {
                t();
            }
        }
    }

    public void setHintTextAppearance(int i) {
        com.google.android.material.internal.b bVar = this.F1;
        bVar.k(i);
        this.t1 = bVar.o;
        if (this.d != null) {
            u(false, false);
            t();
        }
    }

    public void setHintTextColor(ColorStateList colorStateList) {
        if (this.t1 != colorStateList) {
            if (this.s1 == null) {
                com.google.android.material.internal.b bVar = this.F1;
                if (bVar.o != colorStateList) {
                    bVar.o = colorStateList;
                    bVar.i(false);
                }
            }
            this.t1 = colorStateList;
            if (this.d != null) {
                u(false, false);
            }
        }
    }

    public void setLengthCounter(@NonNull w wVar) {
        this.n = wVar;
    }

    public void setMaxEms(int i) {
        this.g = i;
        EditText editText = this.d;
        if (editText == null || i == -1) {
            return;
        }
        editText.setMaxEms(i);
    }

    public void setMaxWidth(int i) {
        this.i = i;
        EditText editText = this.d;
        if (editText == null || i == -1) {
            return;
        }
        editText.setMaxWidth(i);
    }

    public void setMaxWidthResource(int i) {
        setMaxWidth(getContext().getResources().getDimensionPixelSize(i));
    }

    public void setMinEms(int i) {
        this.f = i;
        EditText editText = this.d;
        if (editText == null || i == -1) {
            return;
        }
        editText.setMinEms(i);
    }

    public void setMinWidth(int i) {
        this.h = i;
        EditText editText = this.d;
        if (editText == null || i == -1) {
            return;
        }
        editText.setMinWidth(i);
    }

    public void setMinWidthResource(int i) {
        setMinWidth(getContext().getResources().getDimensionPixelSize(i));
    }

    @Deprecated
    public void setPasswordVisibilityToggleContentDescription(int i) {
        l lVar = this.c;
        lVar.g.setContentDescription(i != 0 ? lVar.getResources().getText(i) : null);
    }

    @Deprecated
    public void setPasswordVisibilityToggleDrawable(int i) {
        l lVar = this.c;
        lVar.g.setImageDrawable(i != 0 ? com.facebook.appevents.g.f(lVar.getContext(), i) : null);
    }

    @Deprecated
    public void setPasswordVisibilityToggleEnabled(boolean z) throws Resources.NotFoundException {
        l lVar = this.c;
        if (z && lVar.i != 1) {
            lVar.g(1);
        } else if (z) {
            lVar.getClass();
        } else {
            lVar.g(0);
        }
    }

    @Deprecated
    public void setPasswordVisibilityToggleTintList(ColorStateList colorStateList) {
        l lVar = this.c;
        lVar.k = colorStateList;
        AbstractC3490l4.a(lVar.a, lVar.g, colorStateList, lVar.l);
    }

    @Deprecated
    public void setPasswordVisibilityToggleTintMode(PorterDuff.Mode mode) {
        l lVar = this.c;
        lVar.l = mode;
        AbstractC3490l4.a(lVar.a, lVar.g, lVar.k, mode);
    }

    public void setPlaceholderText(CharSequence charSequence) {
        if (this.t == null) {
            AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
            this.t = appCompatTextView;
            appCompatTextView.setId(com.quizlet.quizletandroid.R.id.textinput_placeholder);
            AppCompatTextView appCompatTextView2 = this.t;
            WeakHashMap weakHashMap = V.a;
            appCompatTextView2.setImportantForAccessibility(2);
            C1404g c1404gD = d();
            this.w = c1404gD;
            c1404gD.b = 67L;
            this.x = d();
            setPlaceholderTextAppearance(this.v);
            setPlaceholderTextColor(this.u);
        }
        if (TextUtils.isEmpty(charSequence)) {
            setPlaceholderTextEnabled(false);
        } else {
            if (!this.s) {
                setPlaceholderTextEnabled(true);
            }
            this.r = charSequence;
        }
        EditText editText = this.d;
        v(editText == null ? null : editText.getText());
    }

    public void setPlaceholderTextAppearance(int i) {
        this.v = i;
        AppCompatTextView appCompatTextView = this.t;
        if (appCompatTextView != null) {
            appCompatTextView.setTextAppearance(i);
        }
    }

    public void setPlaceholderTextColor(ColorStateList colorStateList) {
        if (this.u != colorStateList) {
            this.u = colorStateList;
            AppCompatTextView appCompatTextView = this.t;
            if (appCompatTextView == null || colorStateList == null) {
                return;
            }
            appCompatTextView.setTextColor(colorStateList);
        }
    }

    public void setPrefixText(CharSequence charSequence) {
        t tVar = this.b;
        tVar.getClass();
        tVar.c = TextUtils.isEmpty(charSequence) ? null : charSequence;
        tVar.b.setText(charSequence);
        tVar.e();
    }

    public void setPrefixTextAppearance(int i) {
        this.b.b.setTextAppearance(i);
    }

    public void setPrefixTextColor(@NonNull ColorStateList colorStateList) {
        this.b.b.setTextColor(colorStateList);
    }

    public void setShapeAppearanceModel(@NonNull com.google.android.material.shape.j jVar) {
        com.google.android.material.shape.g gVar = this.F;
        if (gVar == null || gVar.a.a == jVar) {
            return;
        }
        this.L = jVar;
        b();
    }

    public void setStartIconCheckable(boolean z) {
        this.b.d.setCheckable(z);
    }

    public void setStartIconContentDescription(CharSequence charSequence) {
        CheckableImageButton checkableImageButton = this.b.d;
        if (checkableImageButton.getContentDescription() != charSequence) {
            checkableImageButton.setContentDescription(charSequence);
        }
    }

    public void setStartIconDrawable(int i) {
        setStartIconDrawable(i != 0 ? com.facebook.appevents.g.f(getContext(), i) : null);
    }

    public void setStartIconMinSize(int i) {
        t tVar = this.b;
        if (i < 0) {
            tVar.getClass();
            throw new IllegalArgumentException("startIconSize cannot be less than 0");
        }
        if (i != tVar.g) {
            tVar.g = i;
            CheckableImageButton checkableImageButton = tVar.d;
            checkableImageButton.setMinimumWidth(i);
            checkableImageButton.setMinimumHeight(i);
        }
    }

    public void setStartIconOnClickListener(View.OnClickListener onClickListener) {
        t tVar = this.b;
        View.OnLongClickListener onLongClickListener = tVar.i;
        CheckableImageButton checkableImageButton = tVar.d;
        checkableImageButton.setOnClickListener(onClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setStartIconOnLongClickListener(View.OnLongClickListener onLongClickListener) {
        t tVar = this.b;
        tVar.i = onLongClickListener;
        CheckableImageButton checkableImageButton = tVar.d;
        checkableImageButton.setOnLongClickListener(onLongClickListener);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
    }

    public void setStartIconScaleType(@NonNull ImageView.ScaleType scaleType) {
        t tVar = this.b;
        tVar.h = scaleType;
        tVar.d.setScaleType(scaleType);
    }

    public void setStartIconTintList(ColorStateList colorStateList) {
        t tVar = this.b;
        if (tVar.e != colorStateList) {
            tVar.e = colorStateList;
            AbstractC3490l4.a(tVar.a, tVar.d, colorStateList, tVar.f);
        }
    }

    public void setStartIconTintMode(PorterDuff.Mode mode) {
        t tVar = this.b;
        if (tVar.f != mode) {
            tVar.f = mode;
            AbstractC3490l4.a(tVar.a, tVar.d, tVar.e, mode);
        }
    }

    public void setStartIconVisible(boolean z) {
        this.b.c(z);
    }

    public void setSuffixText(CharSequence charSequence) {
        l lVar = this.c;
        lVar.getClass();
        lVar.p = TextUtils.isEmpty(charSequence) ? null : charSequence;
        lVar.q.setText(charSequence);
        lVar.n();
    }

    public void setSuffixTextAppearance(int i) {
        this.c.q.setTextAppearance(i);
    }

    public void setSuffixTextColor(@NonNull ColorStateList colorStateList) {
        this.c.q.setTextColor(colorStateList);
    }

    public void setTextInputAccessibilityDelegate(v vVar) {
        EditText editText = this.d;
        if (editText != null) {
            V.o(editText, vVar);
        }
    }

    public void setTypeface(Typeface typeface) {
        if (typeface != this.l1) {
            this.l1 = typeface;
            com.google.android.material.internal.b bVar = this.F1;
            boolean zM = bVar.m(typeface);
            boolean zO = bVar.o(typeface);
            if (zM || zO) {
                bVar.i(false);
            }
            p pVar = this.j;
            if (typeface != pVar.B) {
                pVar.B = typeface;
                AppCompatTextView appCompatTextView = pVar.r;
                if (appCompatTextView != null) {
                    appCompatTextView.setTypeface(typeface);
                }
                AppCompatTextView appCompatTextView2 = pVar.y;
                if (appCompatTextView2 != null) {
                    appCompatTextView2.setTypeface(typeface);
                }
            }
            AppCompatTextView appCompatTextView3 = this.o;
            if (appCompatTextView3 != null) {
                appCompatTextView3.setTypeface(typeface);
            }
        }
    }

    public final void t() {
        if (this.W != 1) {
            FrameLayout frameLayout = this.a;
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) frameLayout.getLayoutParams();
            int iC = c();
            if (iC != layoutParams.topMargin) {
                layoutParams.topMargin = iC;
                frameLayout.requestLayout();
            }
        }
    }

    public final void u(boolean z, boolean z2) {
        ColorStateList colorStateList;
        AppCompatTextView appCompatTextView;
        boolean zIsEnabled = isEnabled();
        EditText editText = this.d;
        boolean z3 = (editText == null || TextUtils.isEmpty(editText.getText())) ? false : true;
        EditText editText2 = this.d;
        boolean z4 = editText2 != null && editText2.hasFocus();
        ColorStateList colorStateList2 = this.s1;
        com.google.android.material.internal.b bVar = this.F1;
        if (colorStateList2 != null) {
            bVar.j(colorStateList2);
        }
        if (!zIsEnabled) {
            ColorStateList colorStateList3 = this.s1;
            bVar.j(ColorStateList.valueOf(colorStateList3 != null ? colorStateList3.getColorForState(new int[]{-16842910}, this.C1) : this.C1));
        } else if (m()) {
            AppCompatTextView appCompatTextView2 = this.j.r;
            bVar.j(appCompatTextView2 != null ? appCompatTextView2.getTextColors() : null);
        } else if (this.m && (appCompatTextView = this.o) != null) {
            bVar.j(appCompatTextView.getTextColors());
        } else if (z4 && (colorStateList = this.t1) != null && bVar.o != colorStateList) {
            bVar.o = colorStateList;
            bVar.i(false);
        }
        l lVar = this.c;
        t tVar = this.b;
        if (z3 || !this.G1 || (isEnabled() && z4)) {
            if (z2 || this.E1) {
                ValueAnimator valueAnimator = this.I1;
                if (valueAnimator != null && valueAnimator.isRunning()) {
                    this.I1.cancel();
                }
                if (z && this.H1) {
                    a(1.0f);
                } else {
                    bVar.p(1.0f);
                }
                this.E1 = false;
                if (e()) {
                    j();
                }
                EditText editText3 = this.d;
                v(editText3 != null ? editText3.getText() : null);
                tVar.j = false;
                tVar.e();
                lVar.r = false;
                lVar.n();
                return;
            }
            return;
        }
        if (z2 || !this.E1) {
            ValueAnimator valueAnimator2 = this.I1;
            if (valueAnimator2 != null && valueAnimator2.isRunning()) {
                this.I1.cancel();
            }
            if (z && this.H1) {
                a(DefinitionKt.NO_Float_VALUE);
            } else {
                bVar.p(DefinitionKt.NO_Float_VALUE);
            }
            if (e() && !((g) this.F).y.s.isEmpty() && e()) {
                ((g) this.F).v(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            }
            this.E1 = true;
            AppCompatTextView appCompatTextView3 = this.t;
            if (appCompatTextView3 != null && this.s) {
                appCompatTextView3.setText((CharSequence) null);
                androidx.transition.C.a(this.a, this.x);
                this.t.setVisibility(4);
            }
            tVar.j = true;
            tVar.e();
            lVar.r = true;
            lVar.n();
        }
    }

    public final void v(Editable editable) {
        ((com.facebook.appevents.k) this.n).getClass();
        int length = editable != null ? editable.length() : 0;
        FrameLayout frameLayout = this.a;
        if (length != 0 || this.E1) {
            AppCompatTextView appCompatTextView = this.t;
            if (appCompatTextView == null || !this.s) {
                return;
            }
            appCompatTextView.setText((CharSequence) null);
            androidx.transition.C.a(frameLayout, this.x);
            this.t.setVisibility(4);
            return;
        }
        if (this.t == null || !this.s || TextUtils.isEmpty(this.r)) {
            return;
        }
        this.t.setText(this.r);
        androidx.transition.C.a(frameLayout, this.w);
        this.t.setVisibility(0);
        this.t.bringToFront();
        announceForAccessibility(this.r);
    }

    public final void w(boolean z, boolean z2) {
        int defaultColor = this.x1.getDefaultColor();
        int colorForState = this.x1.getColorForState(new int[]{R.attr.state_hovered, R.attr.state_enabled}, defaultColor);
        int colorForState2 = this.x1.getColorForState(new int[]{R.attr.state_activated, R.attr.state_enabled}, defaultColor);
        if (z) {
            this.g1 = colorForState2;
        } else if (z2) {
            this.g1 = colorForState;
        } else {
            this.g1 = defaultColor;
        }
    }

    public final void x() throws Resources.NotFoundException {
        AppCompatTextView appCompatTextView;
        EditText editText;
        EditText editText2;
        if (this.F == null || this.W == 0) {
            return;
        }
        boolean z = false;
        boolean z2 = isFocused() || ((editText2 = this.d) != null && editText2.hasFocus());
        if (isHovered() || ((editText = this.d) != null && editText.isHovered())) {
            z = true;
        }
        if (!isEnabled()) {
            this.g1 = this.C1;
        } else if (m()) {
            if (this.x1 != null) {
                w(z2, z);
            } else {
                this.g1 = getErrorCurrentTextColors();
            }
        } else if (!this.m || (appCompatTextView = this.o) == null) {
            if (z2) {
                this.g1 = this.w1;
            } else if (z) {
                this.g1 = this.v1;
            } else {
                this.g1 = this.u1;
            }
        } else if (this.x1 != null) {
            w(z2, z);
        } else {
            this.g1 = appCompatTextView.getCurrentTextColor();
        }
        if (Build.VERSION.SDK_INT >= 29) {
            p();
        }
        l lVar = this.c;
        lVar.l();
        CheckableImageButton checkableImageButton = lVar.c;
        ColorStateList colorStateList = lVar.d;
        TextInputLayout textInputLayout = lVar.a;
        AbstractC3490l4.c(textInputLayout, checkableImageButton, colorStateList);
        ColorStateList colorStateList2 = lVar.k;
        CheckableImageButton checkableImageButton2 = lVar.g;
        AbstractC3490l4.c(textInputLayout, checkableImageButton2, colorStateList2);
        if (lVar.b() instanceof i) {
            if (!textInputLayout.m() || checkableImageButton2.getDrawable() == null) {
                AbstractC3490l4.a(textInputLayout, checkableImageButton2, lVar.k, lVar.l);
            } else {
                Drawable drawableMutate = checkableImageButton2.getDrawable().mutate();
                drawableMutate.setTint(textInputLayout.getErrorCurrentTextColors());
                checkableImageButton2.setImageDrawable(drawableMutate);
            }
        }
        t tVar = this.b;
        AbstractC3490l4.c(tVar.a, tVar.d, tVar.e);
        if (this.W == 2) {
            int i = this.d1;
            if (z2 && isEnabled()) {
                this.d1 = this.f1;
            } else {
                this.d1 = this.e1;
            }
            if (this.d1 != i && e() && !this.E1) {
                if (e()) {
                    ((g) this.F).v(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
                }
                j();
            }
        }
        if (this.W == 1) {
            if (!isEnabled()) {
                this.h1 = this.z1;
            } else if (z && !z2) {
                this.h1 = this.B1;
            } else if (z2) {
                this.h1 = this.A1;
            } else {
                this.h1 = this.y1;
            }
        }
        b();
    }

    public TextInputLayout(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, com.quizlet.quizletandroid.R.attr.textInputStyle);
    }

    public void setStartIconDrawable(Drawable drawable) {
        this.b.b(drawable);
    }

    public TextInputLayout(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, i, com.quizlet.quizletandroid.R.style.Widget_Design_TextInputLayout), attributeSet, i);
        this.f = -1;
        this.g = -1;
        this.h = -1;
        this.i = -1;
        this.j = new p(this);
        this.n = new com.facebook.appevents.k(22);
        this.i1 = new Rect();
        this.j1 = new Rect();
        this.k1 = new RectF();
        this.o1 = new LinkedHashSet();
        com.google.android.material.internal.b bVar = new com.google.android.material.internal.b(this);
        this.F1 = bVar;
        this.L1 = false;
        Context context2 = getContext();
        setOrientation(1);
        setWillNotDraw(false);
        setAddStatesFromChildren(true);
        FrameLayout frameLayout = new FrameLayout(context2);
        this.a = frameLayout;
        frameLayout.setAddStatesFromChildren(true);
        LinearInterpolator linearInterpolator = com.google.android.material.animation.a.a;
        bVar.W = linearInterpolator;
        bVar.i(false);
        bVar.V = linearInterpolator;
        bVar.i(false);
        bVar.l(8388659);
        int[] iArr = com.google.android.material.a.S;
        com.google.android.material.internal.p.c(context2, attributeSet, i, com.quizlet.quizletandroid.R.style.Widget_Design_TextInputLayout);
        com.google.android.material.internal.p.d(context2, attributeSet, iArr, i, com.quizlet.quizletandroid.R.style.Widget_Design_TextInputLayout, 22, 20, 40, 45, 49);
        TypedArray typedArrayObtainStyledAttributes = context2.obtainStyledAttributes(attributeSet, iArr, i, com.quizlet.quizletandroid.R.style.Widget_Design_TextInputLayout);
        com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e(context2, typedArrayObtainStyledAttributes);
        t tVar = new t(this, eVar);
        this.b = tVar;
        this.C = typedArrayObtainStyledAttributes.getBoolean(48, true);
        setHint(typedArrayObtainStyledAttributes.getText(4));
        this.H1 = typedArrayObtainStyledAttributes.getBoolean(47, true);
        this.G1 = typedArrayObtainStyledAttributes.getBoolean(42, true);
        if (typedArrayObtainStyledAttributes.hasValue(6)) {
            setMinEms(typedArrayObtainStyledAttributes.getInt(6, -1));
        } else if (typedArrayObtainStyledAttributes.hasValue(3)) {
            setMinWidth(typedArrayObtainStyledAttributes.getDimensionPixelSize(3, -1));
        }
        if (typedArrayObtainStyledAttributes.hasValue(5)) {
            setMaxEms(typedArrayObtainStyledAttributes.getInt(5, -1));
        } else if (typedArrayObtainStyledAttributes.hasValue(2)) {
            setMaxWidth(typedArrayObtainStyledAttributes.getDimensionPixelSize(2, -1));
        }
        this.L = com.google.android.material.shape.j.b(context2, attributeSet, i, com.quizlet.quizletandroid.R.style.Widget_Design_TextInputLayout).a();
        this.V = context2.getResources().getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_textinput_box_label_cutout_padding);
        this.c1 = typedArrayObtainStyledAttributes.getDimensionPixelOffset(9, 0);
        this.e1 = typedArrayObtainStyledAttributes.getDimensionPixelSize(16, context2.getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.mtrl_textinput_box_stroke_width_default));
        this.f1 = typedArrayObtainStyledAttributes.getDimensionPixelSize(17, context2.getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.mtrl_textinput_box_stroke_width_focused));
        this.d1 = this.e1;
        float dimension = typedArrayObtainStyledAttributes.getDimension(13, -1.0f);
        float dimension2 = typedArrayObtainStyledAttributes.getDimension(12, -1.0f);
        float dimension3 = typedArrayObtainStyledAttributes.getDimension(10, -1.0f);
        float dimension4 = typedArrayObtainStyledAttributes.getDimension(11, -1.0f);
        G4 g4F = this.L.f();
        if (dimension >= DefinitionKt.NO_Float_VALUE) {
            g4F.e = new com.google.android.material.shape.a(dimension);
        }
        if (dimension2 >= DefinitionKt.NO_Float_VALUE) {
            g4F.f = new com.google.android.material.shape.a(dimension2);
        }
        if (dimension3 >= DefinitionKt.NO_Float_VALUE) {
            g4F.g = new com.google.android.material.shape.a(dimension3);
        }
        if (dimension4 >= DefinitionKt.NO_Float_VALUE) {
            g4F.h = new com.google.android.material.shape.a(dimension4);
        }
        this.L = g4F.a();
        ColorStateList colorStateListB = AbstractC3442d4.b(context2, eVar, 7);
        if (colorStateListB != null) {
            int defaultColor = colorStateListB.getDefaultColor();
            this.y1 = defaultColor;
            this.h1 = defaultColor;
            if (colorStateListB.isStateful()) {
                this.z1 = colorStateListB.getColorForState(new int[]{-16842910}, -1);
                this.A1 = colorStateListB.getColorForState(new int[]{R.attr.state_focused, R.attr.state_enabled}, -1);
                this.B1 = colorStateListB.getColorForState(new int[]{R.attr.state_hovered, R.attr.state_enabled}, -1);
            } else {
                this.A1 = this.y1;
                ColorStateList colorStateListC = androidx.core.content.c.c(context2, com.quizlet.quizletandroid.R.color.mtrl_filled_background_color);
                this.z1 = colorStateListC.getColorForState(new int[]{-16842910}, -1);
                this.B1 = colorStateListC.getColorForState(new int[]{R.attr.state_hovered}, -1);
            }
        } else {
            this.h1 = 0;
            this.y1 = 0;
            this.z1 = 0;
            this.A1 = 0;
            this.B1 = 0;
        }
        if (typedArrayObtainStyledAttributes.hasValue(1)) {
            ColorStateList colorStateListE = eVar.e(1);
            this.t1 = colorStateListE;
            this.s1 = colorStateListE;
        }
        ColorStateList colorStateListB2 = AbstractC3442d4.b(context2, eVar, 14);
        this.w1 = typedArrayObtainStyledAttributes.getColor(14, 0);
        this.u1 = context2.getColor(com.quizlet.quizletandroid.R.color.mtrl_textinput_default_box_stroke_color);
        this.C1 = context2.getColor(com.quizlet.quizletandroid.R.color.mtrl_textinput_disabled_color);
        this.v1 = context2.getColor(com.quizlet.quizletandroid.R.color.mtrl_textinput_hovered_box_stroke_color);
        if (colorStateListB2 != null) {
            setBoxStrokeColorStateList(colorStateListB2);
        }
        if (typedArrayObtainStyledAttributes.hasValue(15)) {
            setBoxStrokeErrorColor(AbstractC3442d4.b(context2, eVar, 15));
        }
        if (typedArrayObtainStyledAttributes.getResourceId(49, -1) != -1) {
            setHintTextAppearance(typedArrayObtainStyledAttributes.getResourceId(49, 0));
        }
        this.A = eVar.e(24);
        this.B = eVar.e(25);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(40, 0);
        CharSequence text = typedArrayObtainStyledAttributes.getText(35);
        int i2 = typedArrayObtainStyledAttributes.getInt(34, 1);
        boolean z = typedArrayObtainStyledAttributes.getBoolean(36, false);
        int resourceId2 = typedArrayObtainStyledAttributes.getResourceId(45, 0);
        boolean z2 = typedArrayObtainStyledAttributes.getBoolean(44, false);
        CharSequence text2 = typedArrayObtainStyledAttributes.getText(43);
        int resourceId3 = typedArrayObtainStyledAttributes.getResourceId(57, 0);
        CharSequence text3 = typedArrayObtainStyledAttributes.getText(56);
        boolean z3 = typedArrayObtainStyledAttributes.getBoolean(18, false);
        setCounterMaxLength(typedArrayObtainStyledAttributes.getInt(19, -1));
        this.q = typedArrayObtainStyledAttributes.getResourceId(22, 0);
        this.p = typedArrayObtainStyledAttributes.getResourceId(20, 0);
        setBoxBackgroundMode(typedArrayObtainStyledAttributes.getInt(8, 0));
        setErrorContentDescription(text);
        setErrorAccessibilityLiveRegion(i2);
        setCounterOverflowTextAppearance(this.p);
        setHelperTextTextAppearance(resourceId2);
        setErrorTextAppearance(resourceId);
        setCounterTextAppearance(this.q);
        setPlaceholderText(text3);
        setPlaceholderTextAppearance(resourceId3);
        if (typedArrayObtainStyledAttributes.hasValue(41)) {
            setErrorTextColor(eVar.e(41));
        }
        if (typedArrayObtainStyledAttributes.hasValue(46)) {
            setHelperTextColor(eVar.e(46));
        }
        if (typedArrayObtainStyledAttributes.hasValue(50)) {
            setHintTextColor(eVar.e(50));
        }
        if (typedArrayObtainStyledAttributes.hasValue(23)) {
            setCounterTextColor(eVar.e(23));
        }
        if (typedArrayObtainStyledAttributes.hasValue(21)) {
            setCounterOverflowTextColor(eVar.e(21));
        }
        if (typedArrayObtainStyledAttributes.hasValue(58)) {
            setPlaceholderTextColor(eVar.e(58));
        }
        l lVar = new l(this, eVar);
        this.c = lVar;
        boolean z4 = typedArrayObtainStyledAttributes.getBoolean(0, true);
        eVar.n();
        WeakHashMap weakHashMap = V.a;
        setImportantForAccessibility(2);
        O.b(this, 1);
        frameLayout.addView(tVar);
        frameLayout.addView(lVar);
        addView(frameLayout);
        setEnabled(z4);
        setHelperTextEnabled(z2);
        setErrorEnabled(z);
        setCounterEnabled(z3);
        setHelperText(text2);
    }

    public void setHint(int i) {
        setHint(i != 0 ? getResources().getText(i) : null);
    }

    public void setStartIconContentDescription(int i) {
        setStartIconContentDescription(i != 0 ? getResources().getText(i) : null);
    }

    @Deprecated
    public void setPasswordVisibilityToggleContentDescription(CharSequence charSequence) {
        this.c.g.setContentDescription(charSequence);
    }

    @Deprecated
    public void setPasswordVisibilityToggleDrawable(Drawable drawable) {
        this.c.g.setImageDrawable(drawable);
    }

    public void setErrorIconDrawable(Drawable drawable) throws Resources.NotFoundException {
        this.c.i(drawable);
    }

    public void setEndIconContentDescription(CharSequence charSequence) {
        CheckableImageButton checkableImageButton = this.c.g;
        if (checkableImageButton.getContentDescription() != charSequence) {
            checkableImageButton.setContentDescription(charSequence);
        }
    }

    public void setEndIconDrawable(Drawable drawable) {
        l lVar = this.c;
        CheckableImageButton checkableImageButton = lVar.g;
        checkableImageButton.setImageDrawable(drawable);
        if (drawable != null) {
            ColorStateList colorStateList = lVar.k;
            PorterDuff.Mode mode = lVar.l;
            TextInputLayout textInputLayout = lVar.a;
            AbstractC3490l4.a(textInputLayout, checkableImageButton, colorStateList, mode);
            AbstractC3490l4.c(textInputLayout, checkableImageButton, lVar.k);
        }
    }
}
