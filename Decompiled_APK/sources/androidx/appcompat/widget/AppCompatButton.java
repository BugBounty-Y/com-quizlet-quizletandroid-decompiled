package androidx.appcompat.widget;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.InputFilter;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Button;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes.dex */
public class AppCompatButton extends Button implements androidx.core.widget.b {
    public final C0105q a;
    public final Z b;
    public C0118x c;

    public AppCompatButton(@NonNull Context context) {
        this(context, null);
    }

    @NonNull
    private C0118x getEmojiTextViewHelper() {
        if (this.c == null) {
            this.c = new C0118x(this);
        }
        return this.c;
    }

    @Override // android.widget.TextView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.a();
        }
        Z z = this.b;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public int getAutoSizeMaxTextSize() {
        if (C1.c) {
            return super.getAutoSizeMaxTextSize();
        }
        Z z = this.b;
        if (z != null) {
            return Math.round(z.i.e);
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int getAutoSizeMinTextSize() {
        if (C1.c) {
            return super.getAutoSizeMinTextSize();
        }
        Z z = this.b;
        if (z != null) {
            return Math.round(z.i.d);
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int getAutoSizeStepGranularity() {
        if (C1.c) {
            return super.getAutoSizeStepGranularity();
        }
        Z z = this.b;
        if (z != null) {
            return Math.round(z.i.c);
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int[] getAutoSizeTextAvailableSizes() {
        if (C1.c) {
            return super.getAutoSizeTextAvailableSizes();
        }
        Z z = this.b;
        return z != null ? z.i.f : new int[0];
    }

    @Override // android.widget.TextView
    @SuppressLint({"WrongConstant"})
    public int getAutoSizeTextType() {
        if (C1.c) {
            return super.getAutoSizeTextType() == 1 ? 1 : 0;
        }
        Z z = this.b;
        if (z != null) {
            return z.i.a;
        }
        return 0;
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return B6.h(super.getCustomSelectionActionModeCallback());
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            return c0105q.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            return c0105q.c();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.b.d();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.b.e();
    }

    @Override // android.view.View
    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName(Button.class.getName());
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName(Button.class.getName());
    }

    @Override // android.widget.TextView, android.view.View
    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        Z z2 = this.b;
        if (z2 == null || C1.c) {
            return;
        }
        z2.i.a();
    }

    @Override // android.widget.TextView
    public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        super.onTextChanged(charSequence, i, i2, i3);
        Z z = this.b;
        if (z == null || C1.c) {
            return;
        }
        C0088h0 c0088h0 = z.i;
        if (c0088h0.f()) {
            c0088h0.a();
        }
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z) {
        super.setAllCaps(z);
        getEmojiTextViewHelper().c(z);
    }

    @Override // android.widget.TextView, androidx.core.widget.b
    public final void setAutoSizeTextTypeUniformWithConfiguration(int i, int i2, int i3, int i4) {
        if (C1.c) {
            super.setAutoSizeTextTypeUniformWithConfiguration(i, i2, i3, i4);
            return;
        }
        Z z = this.b;
        if (z != null) {
            z.h(i, i2, i3, i4);
        }
    }

    @Override // android.widget.TextView
    public final void setAutoSizeTextTypeUniformWithPresetSizes(int[] iArr, int i) {
        if (C1.c) {
            super.setAutoSizeTextTypeUniformWithPresetSizes(iArr, i);
            return;
        }
        Z z = this.b;
        if (z != null) {
            z.i(iArr, i);
        }
    }

    @Override // android.widget.TextView
    public void setAutoSizeTextTypeWithDefaults(int i) {
        if (C1.c) {
            super.setAutoSizeTextTypeWithDefaults(i);
            return;
        }
        Z z = this.b;
        if (z != null) {
            z.j(i);
        }
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.e();
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.f(i);
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(B6.i(callback, this));
    }

    public void setEmojiCompatEnabled(boolean z) {
        getEmojiTextViewHelper().d(z);
    }

    @Override // android.widget.TextView
    public void setFilters(@NonNull InputFilter[] inputFilterArr) {
        super.setFilters(getEmojiTextViewHelper().a(inputFilterArr));
    }

    public void setSupportAllCaps(boolean z) {
        Z z2 = this.b;
        if (z2 != null) {
            z2.a.setAllCaps(z);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.h(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.i(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        Z z = this.b;
        z.k(colorStateList);
        z.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        Z z = this.b;
        z.l(mode);
        z.b();
    }

    @Override // android.widget.TextView
    public final void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        Z z = this.b;
        if (z != null) {
            z.g(context, i);
        }
    }

    @Override // android.widget.TextView
    public final void setTextSize(int i, float f) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        boolean z = C1.c;
        if (z) {
            super.setTextSize(i, f);
            return;
        }
        Z z2 = this.b;
        if (z2 == null || z) {
            return;
        }
        C0088h0 c0088h0 = z2.i;
        if (c0088h0.f()) {
            return;
        }
        c0088h0.g(f, i);
    }

    public AppCompatButton(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.buttonStyle);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AppCompatButton(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        n1.a(context);
        m1.a(getContext(), this);
        C0105q c0105q = new C0105q(this);
        this.a = c0105q;
        c0105q.d(attributeSet, i);
        Z z = new Z(this);
        this.b = z;
        z.f(attributeSet, i);
        z.b();
        getEmojiTextViewHelper().b(attributeSet, i);
    }
}
