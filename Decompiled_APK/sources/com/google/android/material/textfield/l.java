package com.google.android.material.textfield;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.appcompat.view.menu.ViewOnAttachStateChangeListenerC0068e;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3490l4;
import com.google.android.material.internal.CheckableImageButton;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class l extends LinearLayout {
    public final TextInputLayout a;
    public final FrameLayout b;
    public final CheckableImageButton c;
    public ColorStateList d;
    public PorterDuff.Mode e;
    public View.OnLongClickListener f;
    public final CheckableImageButton g;
    public final androidx.compose.ui.text.android.selection.f h;
    public int i;
    public final LinkedHashSet j;
    public ColorStateList k;
    public PorterDuff.Mode l;
    public int m;
    public ImageView.ScaleType n;
    public View.OnLongClickListener o;
    public CharSequence p;
    public final AppCompatTextView q;
    public boolean r;
    public EditText s;
    public final AccessibilityManager t;
    public com.google.android.material.search.a u;
    public final j v;

    public l(TextInputLayout textInputLayout, com.quizlet.data.repository.classfolder.e eVar) throws Resources.NotFoundException {
        CharSequence text;
        super(textInputLayout.getContext());
        this.i = 0;
        this.j = new LinkedHashSet();
        this.v = new j(this);
        k kVar = new k(this);
        this.t = (AccessibilityManager) getContext().getSystemService("accessibility");
        this.a = textInputLayout;
        setVisibility(8);
        setOrientation(0);
        setLayoutParams(new FrameLayout.LayoutParams(-2, -1, 8388613));
        FrameLayout frameLayout = new FrameLayout(getContext());
        this.b = frameLayout;
        frameLayout.setVisibility(8);
        frameLayout.setLayoutParams(new LinearLayout.LayoutParams(-2, -1));
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(getContext());
        CheckableImageButton checkableImageButtonA = a(this, layoutInflaterFrom, R.id.text_input_error_icon);
        this.c = checkableImageButtonA;
        CheckableImageButton checkableImageButtonA2 = a(frameLayout, layoutInflaterFrom, R.id.text_input_end_icon);
        this.g = checkableImageButtonA2;
        this.h = new androidx.compose.ui.text.android.selection.f(this, eVar);
        AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
        this.q = appCompatTextView;
        TypedArray typedArray = (TypedArray) eVar.c;
        if (typedArray.hasValue(38)) {
            this.d = AbstractC3442d4.b(getContext(), eVar, 38);
        }
        if (typedArray.hasValue(39)) {
            this.e = com.google.android.material.internal.p.m(typedArray.getInt(39, -1), null);
        }
        if (typedArray.hasValue(37)) {
            i(eVar.f(37));
        }
        checkableImageButtonA.setContentDescription(getResources().getText(R.string.error_icon_content_description));
        WeakHashMap weakHashMap = V.a;
        checkableImageButtonA.setImportantForAccessibility(2);
        checkableImageButtonA.setClickable(false);
        checkableImageButtonA.setPressable(false);
        checkableImageButtonA.setFocusable(false);
        if (!typedArray.hasValue(53)) {
            if (typedArray.hasValue(32)) {
                this.k = AbstractC3442d4.b(getContext(), eVar, 32);
            }
            if (typedArray.hasValue(33)) {
                this.l = com.google.android.material.internal.p.m(typedArray.getInt(33, -1), null);
            }
        }
        if (typedArray.hasValue(30)) {
            g(typedArray.getInt(30, 0));
            if (typedArray.hasValue(27) && checkableImageButtonA2.getContentDescription() != (text = typedArray.getText(27))) {
                checkableImageButtonA2.setContentDescription(text);
            }
            checkableImageButtonA2.setCheckable(typedArray.getBoolean(26, true));
        } else if (typedArray.hasValue(53)) {
            if (typedArray.hasValue(54)) {
                this.k = AbstractC3442d4.b(getContext(), eVar, 54);
            }
            if (typedArray.hasValue(55)) {
                this.l = com.google.android.material.internal.p.m(typedArray.getInt(55, -1), null);
            }
            g(typedArray.getBoolean(53, false) ? 1 : 0);
            CharSequence text2 = typedArray.getText(51);
            if (checkableImageButtonA2.getContentDescription() != text2) {
                checkableImageButtonA2.setContentDescription(text2);
            }
        }
        int dimensionPixelSize = typedArray.getDimensionPixelSize(29, getResources().getDimensionPixelSize(R.dimen.mtrl_min_touch_target_size));
        if (dimensionPixelSize < 0) {
            throw new IllegalArgumentException("endIconSize cannot be less than 0");
        }
        if (dimensionPixelSize != this.m) {
            this.m = dimensionPixelSize;
            checkableImageButtonA2.setMinimumWidth(dimensionPixelSize);
            checkableImageButtonA2.setMinimumHeight(dimensionPixelSize);
            checkableImageButtonA.setMinimumWidth(dimensionPixelSize);
            checkableImageButtonA.setMinimumHeight(dimensionPixelSize);
        }
        if (typedArray.hasValue(31)) {
            ImageView.ScaleType scaleTypeB = AbstractC3490l4.b(typedArray.getInt(31, -1));
            this.n = scaleTypeB;
            checkableImageButtonA2.setScaleType(scaleTypeB);
            checkableImageButtonA.setScaleType(scaleTypeB);
        }
        appCompatTextView.setVisibility(8);
        appCompatTextView.setId(R.id.textinput_suffix_text);
        appCompatTextView.setLayoutParams(new LinearLayout.LayoutParams(-2, -2, 80.0f));
        appCompatTextView.setAccessibilityLiveRegion(1);
        appCompatTextView.setTextAppearance(typedArray.getResourceId(72, 0));
        if (typedArray.hasValue(73)) {
            appCompatTextView.setTextColor(eVar.e(73));
        }
        CharSequence text3 = typedArray.getText(71);
        this.p = TextUtils.isEmpty(text3) ? null : text3;
        appCompatTextView.setText(text3);
        n();
        frameLayout.addView(checkableImageButtonA2);
        addView(appCompatTextView);
        addView(frameLayout);
        addView(checkableImageButtonA);
        textInputLayout.o1.add(kVar);
        if (textInputLayout.d != null) {
            kVar.a(textInputLayout);
        }
        addOnAttachStateChangeListener(new ViewOnAttachStateChangeListenerC0068e(this, 6));
    }

    public final CheckableImageButton a(ViewGroup viewGroup, LayoutInflater layoutInflater, int i) {
        CheckableImageButton checkableImageButton = (CheckableImageButton) layoutInflater.inflate(R.layout.design_text_input_end_icon, viewGroup, false);
        checkableImageButton.setId(i);
        if (AbstractC3442d4.e(getContext())) {
            ((ViewGroup.MarginLayoutParams) checkableImageButton.getLayoutParams()).setMarginStart(0);
        }
        return checkableImageButton;
    }

    public final m b() {
        m eVar;
        int i = this.i;
        androidx.compose.ui.text.android.selection.f fVar = this.h;
        SparseArray sparseArray = (SparseArray) fVar.d;
        m mVar = (m) sparseArray.get(i);
        if (mVar != null) {
            return mVar;
        }
        l lVar = (l) fVar.e;
        if (i == -1) {
            eVar = new e(lVar, 0);
        } else if (i == 0) {
            eVar = new e(lVar, 1);
        } else if (i == 1) {
            eVar = new s(lVar, fVar.c);
        } else if (i == 2) {
            eVar = new d(lVar);
        } else {
            if (i != 3) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Invalid end icon mode: "));
            }
            eVar = new i(lVar);
        }
        sparseArray.append(i, eVar);
        return eVar;
    }

    public final int c() {
        int marginStart;
        if (d() || e()) {
            CheckableImageButton checkableImageButton = this.g;
            marginStart = ((ViewGroup.MarginLayoutParams) checkableImageButton.getLayoutParams()).getMarginStart() + checkableImageButton.getMeasuredWidth();
        } else {
            marginStart = 0;
        }
        WeakHashMap weakHashMap = V.a;
        return this.q.getPaddingEnd() + getPaddingEnd() + marginStart;
    }

    public final boolean d() {
        return this.b.getVisibility() == 0 && this.g.getVisibility() == 0;
    }

    public final boolean e() {
        return this.c.getVisibility() == 0;
    }

    public final void f(boolean z) {
        boolean z2;
        boolean zIsActivated;
        boolean z3;
        m mVarB = b();
        boolean zK = mVarB.k();
        CheckableImageButton checkableImageButton = this.g;
        boolean z4 = true;
        if (!zK || (z3 = checkableImageButton.d) == mVarB.l()) {
            z2 = false;
        } else {
            checkableImageButton.setChecked(!z3);
            z2 = true;
        }
        if (!(mVarB instanceof i) || (zIsActivated = checkableImageButton.isActivated()) == mVarB.j()) {
            z4 = z2;
        } else {
            checkableImageButton.setActivated(!zIsActivated);
        }
        if (z || z4) {
            AbstractC3490l4.c(this.a, checkableImageButton, this.k);
        }
    }

    public final void g(int i) throws Resources.NotFoundException {
        if (this.i == i) {
            return;
        }
        m mVarB = b();
        com.google.android.material.search.a aVar = this.u;
        AccessibilityManager accessibilityManager = this.t;
        if (aVar != null && accessibilityManager != null) {
            accessibilityManager.removeTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(aVar));
        }
        this.u = null;
        mVarB.s();
        this.i = i;
        Iterator it2 = this.j.iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        h(i != 0);
        m mVarB2 = b();
        int iD = this.h.b;
        if (iD == 0) {
            iD = mVarB2.d();
        }
        Drawable drawableF = iD != 0 ? com.facebook.appevents.g.f(getContext(), iD) : null;
        CheckableImageButton checkableImageButton = this.g;
        checkableImageButton.setImageDrawable(drawableF);
        TextInputLayout textInputLayout = this.a;
        if (drawableF != null) {
            AbstractC3490l4.a(textInputLayout, checkableImageButton, this.k, this.l);
            AbstractC3490l4.c(textInputLayout, checkableImageButton, this.k);
        }
        int iC = mVarB2.c();
        CharSequence text = iC != 0 ? getResources().getText(iC) : null;
        if (checkableImageButton.getContentDescription() != text) {
            checkableImageButton.setContentDescription(text);
        }
        checkableImageButton.setCheckable(mVarB2.k());
        if (!mVarB2.i(textInputLayout.getBoxBackgroundMode())) {
            throw new IllegalStateException("The current box background mode " + textInputLayout.getBoxBackgroundMode() + " is not supported by the end icon mode " + i);
        }
        mVarB2.r();
        com.google.android.material.search.a aVarH = mVarB2.h();
        this.u = aVarH;
        if (aVarH != null && accessibilityManager != null) {
            WeakHashMap weakHashMap = V.a;
            if (isAttachedToWindow()) {
                accessibilityManager.addTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(this.u));
            }
        }
        View.OnClickListener onClickListenerF = mVarB2.f();
        View.OnLongClickListener onLongClickListener = this.o;
        checkableImageButton.setOnClickListener(onClickListenerF);
        AbstractC3490l4.d(checkableImageButton, onLongClickListener);
        EditText editText = this.s;
        if (editText != null) {
            mVarB2.m(editText);
            j(mVarB2);
        }
        AbstractC3490l4.a(textInputLayout, checkableImageButton, this.k, this.l);
        f(true);
    }

    public final void h(boolean z) throws Resources.NotFoundException {
        if (d() != z) {
            this.g.setVisibility(z ? 0 : 8);
            k();
            m();
            this.a.q();
        }
    }

    public final void i(Drawable drawable) throws Resources.NotFoundException {
        CheckableImageButton checkableImageButton = this.c;
        checkableImageButton.setImageDrawable(drawable);
        l();
        AbstractC3490l4.a(this.a, checkableImageButton, this.d, this.e);
    }

    public final void j(m mVar) {
        if (this.s == null) {
            return;
        }
        if (mVar.e() != null) {
            this.s.setOnFocusChangeListener(mVar.e());
        }
        if (mVar.g() != null) {
            this.g.setOnFocusChangeListener(mVar.g());
        }
    }

    public final void k() {
        this.b.setVisibility((this.g.getVisibility() != 0 || e()) ? 8 : 0);
        setVisibility((d() || e() || !((this.p == null || this.r) ? 8 : false)) ? 0 : 8);
    }

    public final void l() throws Resources.NotFoundException {
        CheckableImageButton checkableImageButton = this.c;
        Drawable drawable = checkableImageButton.getDrawable();
        TextInputLayout textInputLayout = this.a;
        checkableImageButton.setVisibility((drawable != null && textInputLayout.j.q && textInputLayout.m()) ? 0 : 8);
        k();
        m();
        if (this.i != 0) {
            return;
        }
        textInputLayout.q();
    }

    public final void m() throws Resources.NotFoundException {
        int paddingEnd;
        TextInputLayout textInputLayout = this.a;
        if (textInputLayout.d == null) {
            return;
        }
        if (d() || e()) {
            paddingEnd = 0;
        } else {
            EditText editText = textInputLayout.d;
            WeakHashMap weakHashMap = V.a;
            paddingEnd = editText.getPaddingEnd();
        }
        int dimensionPixelSize = getContext().getResources().getDimensionPixelSize(R.dimen.material_input_text_to_prefix_suffix_padding);
        int paddingTop = textInputLayout.d.getPaddingTop();
        int paddingBottom = textInputLayout.d.getPaddingBottom();
        WeakHashMap weakHashMap2 = V.a;
        this.q.setPaddingRelative(dimensionPixelSize, paddingTop, paddingEnd, paddingBottom);
    }

    public final void n() {
        AppCompatTextView appCompatTextView = this.q;
        int visibility = appCompatTextView.getVisibility();
        int i = (this.p == null || this.r) ? 8 : 0;
        if (visibility != i) {
            b().p(i == 0);
        }
        k();
        appCompatTextView.setVisibility(i);
        this.a.q();
    }
}
