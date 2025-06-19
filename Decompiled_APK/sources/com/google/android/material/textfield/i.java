package com.google.android.material.textfield;

import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.Spinner;
import androidx.appcompat.widget.C0076c;
import androidx.compose.ui.text.input.C;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3472i4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class i extends m {
    public final int e;
    public final int f;
    public final TimeInterpolator g;
    public AutoCompleteTextView h;
    public final com.braze.ui.inappmessage.d i;
    public final a j;
    public final com.google.android.material.search.a k;
    public boolean l;
    public boolean m;
    public boolean n;
    public long o;
    public AccessibilityManager p;
    public ValueAnimator q;
    public ValueAnimator r;

    public i(l lVar) {
        super(lVar);
        this.i = new com.braze.ui.inappmessage.d(this, 6);
        int i = 1;
        this.j = new a(this, i);
        this.k = new com.google.android.material.search.a(this, i);
        this.o = Long.MAX_VALUE;
        this.f = AbstractC3430b4.d(lVar.getContext(), R.attr.motionDurationShort3, 67);
        this.e = AbstractC3430b4.d(lVar.getContext(), R.attr.motionDurationShort3, 50);
        this.g = AbstractC3430b4.e(lVar.getContext(), R.attr.motionEasingLinearInterpolator, com.google.android.material.animation.a.a);
    }

    @Override // com.google.android.material.textfield.m
    public final void a() {
        if (this.p.isTouchExplorationEnabled() && AbstractC3472i4.a(this.h) && !this.d.hasFocus()) {
            this.h.dismissDropDown();
        }
        this.h.post(new C(this, 26));
    }

    @Override // com.google.android.material.textfield.m
    public final int c() {
        return R.string.exposed_dropdown_menu_content_description;
    }

    @Override // com.google.android.material.textfield.m
    public final int d() {
        return R.drawable.mtrl_dropdown_arrow;
    }

    @Override // com.google.android.material.textfield.m
    public final View.OnFocusChangeListener e() {
        return this.j;
    }

    @Override // com.google.android.material.textfield.m
    public final View.OnClickListener f() {
        return this.i;
    }

    @Override // com.google.android.material.textfield.m
    public final com.google.android.material.search.a h() {
        return this.k;
    }

    @Override // com.google.android.material.textfield.m
    public final boolean i(int i) {
        return i != 0;
    }

    @Override // com.google.android.material.textfield.m
    public final boolean j() {
        return this.l;
    }

    @Override // com.google.android.material.textfield.m
    public final boolean l() {
        return this.n;
    }

    @Override // com.google.android.material.textfield.m
    public final void m(EditText editText) throws Resources.NotFoundException {
        if (!(editText instanceof AutoCompleteTextView)) {
            throw new RuntimeException("EditText needs to be an AutoCompleteTextView if an Exposed Dropdown Menu is being used.");
        }
        AutoCompleteTextView autoCompleteTextView = (AutoCompleteTextView) editText;
        this.h = autoCompleteTextView;
        autoCompleteTextView.setOnTouchListener(new com.amazon.aps.ads.util.adview.d(this, 3));
        this.h.setOnDismissListener(new AutoCompleteTextView.OnDismissListener() { // from class: com.google.android.material.textfield.h
            @Override // android.widget.AutoCompleteTextView.OnDismissListener
            public final void onDismiss() {
                i iVar = this.a;
                iVar.m = true;
                iVar.o = System.currentTimeMillis();
                iVar.t(false);
            }
        });
        this.h.setThreshold(0);
        TextInputLayout textInputLayout = this.a;
        textInputLayout.setErrorIconDrawable((Drawable) null);
        if (!AbstractC3472i4.a(editText) && this.p.isTouchExplorationEnabled()) {
            WeakHashMap weakHashMap = V.a;
            this.d.setImportantForAccessibility(2);
        }
        textInputLayout.setEndIconVisible(true);
    }

    @Override // com.google.android.material.textfield.m
    public final void n(androidx.core.view.accessibility.e eVar) {
        if (!AbstractC3472i4.a(this.h)) {
            eVar.i(Spinner.class.getName());
        }
        AccessibilityNodeInfo accessibilityNodeInfo = eVar.a;
        if (accessibilityNodeInfo.isShowingHintText()) {
            accessibilityNodeInfo.setHintText(null);
        }
    }

    @Override // com.google.android.material.textfield.m
    public final void o(AccessibilityEvent accessibilityEvent) {
        if (!this.p.isEnabled() || AbstractC3472i4.a(this.h)) {
            return;
        }
        boolean z = (accessibilityEvent.getEventType() == 32768 || accessibilityEvent.getEventType() == 8) && this.n && !this.h.isPopupShowing();
        if (accessibilityEvent.getEventType() == 1 || z) {
            u();
            this.m = true;
            this.o = System.currentTimeMillis();
        }
    }

    @Override // com.google.android.material.textfield.m
    public final void r() {
        int i = 5;
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        TimeInterpolator timeInterpolator = this.g;
        valueAnimatorOfFloat.setInterpolator(timeInterpolator);
        valueAnimatorOfFloat.setDuration(this.f);
        valueAnimatorOfFloat.addUpdateListener(new com.airbnb.lottie.s(this, i));
        this.r = valueAnimatorOfFloat;
        ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(1.0f, DefinitionKt.NO_Float_VALUE);
        valueAnimatorOfFloat2.setInterpolator(timeInterpolator);
        valueAnimatorOfFloat2.setDuration(this.e);
        valueAnimatorOfFloat2.addUpdateListener(new com.airbnb.lottie.s(this, i));
        this.q = valueAnimatorOfFloat2;
        valueAnimatorOfFloat2.addListener(new C0076c(this, 11));
        this.p = (AccessibilityManager) this.c.getSystemService("accessibility");
    }

    @Override // com.google.android.material.textfield.m
    public final void s() {
        AutoCompleteTextView autoCompleteTextView = this.h;
        if (autoCompleteTextView != null) {
            autoCompleteTextView.setOnTouchListener(null);
            this.h.setOnDismissListener(null);
        }
    }

    public final void t(boolean z) {
        if (this.n != z) {
            this.n = z;
            this.r.cancel();
            this.q.start();
        }
    }

    public final void u() {
        if (this.h == null) {
            return;
        }
        long jCurrentTimeMillis = System.currentTimeMillis() - this.o;
        if (jCurrentTimeMillis < 0 || jCurrentTimeMillis > 300) {
            this.m = false;
        }
        if (this.m) {
            this.m = false;
            return;
        }
        t(!this.n);
        if (!this.n) {
            this.h.dismissDropDown();
        } else {
            this.h.requestFocus();
            this.h.showDropDown();
        }
    }
}
