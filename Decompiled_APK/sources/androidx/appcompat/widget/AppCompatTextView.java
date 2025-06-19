package androidx.appcompat.widget;

import android.R;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.InputFilter;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ActionMode;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.view.textclassifier.TextClassifier;
import android.widget.TextView;
import androidx.activity.AbstractC0029a;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/* loaded from: classes.dex */
public class AppCompatTextView extends TextView implements androidx.core.widget.b {
    private final C0105q mBackgroundTintHelper;

    @NonNull
    private C0118x mEmojiTextViewHelper;
    private boolean mIsSetTypefaceProcessing;
    private Future<androidx.core.text.d> mPrecomputedTextFuture;
    private InterfaceC0071a0 mSuperCaller;
    private final T mTextClassifierHelper;
    private final Z mTextHelper;

    public AppCompatTextView(@NonNull Context context) {
        this(context, null);
    }

    @NonNull
    private C0118x getEmojiTextViewHelper() {
        if (this.mEmojiTextViewHelper == null) {
            this.mEmojiTextViewHelper = new C0118x(this);
        }
        return this.mEmojiTextViewHelper;
    }

    public final void c() {
        Future<androidx.core.text.d> future = this.mPrecomputedTextFuture;
        if (future == null) {
            return;
        }
        try {
            this.mPrecomputedTextFuture = null;
            if (future.get() != null) {
                throw new ClassCastException();
            }
            if (Build.VERSION.SDK_INT >= 29) {
                throw null;
            }
            B6.a(this);
            throw null;
        } catch (InterruptedException | ExecutionException unused) {
        }
    }

    @Override // android.widget.TextView, android.view.View
    public void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            c0105q.a();
        }
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public int getAutoSizeMaxTextSize() {
        if (C1.c) {
            return super.getAutoSizeMaxTextSize();
        }
        Z z = this.mTextHelper;
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
        Z z = this.mTextHelper;
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
        Z z = this.mTextHelper;
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
        Z z = this.mTextHelper;
        return z != null ? z.i.f : new int[0];
    }

    @Override // android.widget.TextView
    @SuppressLint({"WrongConstant"})
    public int getAutoSizeTextType() {
        if (C1.c) {
            return super.getAutoSizeTextType() == 1 ? 1 : 0;
        }
        Z z = this.mTextHelper;
        if (z != null) {
            return z.i.a;
        }
        return 0;
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return B6.h(super.getCustomSelectionActionModeCallback());
    }

    @Override // android.widget.TextView
    public int getFirstBaselineToTopHeight() {
        return getPaddingTop() - getPaint().getFontMetricsInt().top;
    }

    @Override // android.widget.TextView
    public int getLastBaselineToBottomHeight() {
        return getPaddingBottom() + getPaint().getFontMetricsInt().bottom;
    }

    public InterfaceC0071a0 getSuperCaller() {
        if (this.mSuperCaller == null) {
            int i = Build.VERSION.SDK_INT;
            if (i >= 34) {
                this.mSuperCaller = new C0077c0(this);
            } else if (i >= 28) {
                this.mSuperCaller = new C0074b0(this);
            } else {
                this.mSuperCaller = new com.google.firebase.platforminfo.c(this);
            }
        }
        return this.mSuperCaller;
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            return c0105q.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            return c0105q.c();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.mTextHelper.d();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.mTextHelper.e();
    }

    @Override // android.widget.TextView
    public CharSequence getText() {
        c();
        return super.getText();
    }

    @Override // android.widget.TextView
    @NonNull
    public TextClassifier getTextClassifier() {
        T t;
        if (Build.VERSION.SDK_INT >= 28 || (t = this.mTextClassifierHelper) == null) {
            return super.getTextClassifier();
        }
        TextClassifier textClassifier = t.b;
        return textClassifier == null ? S.a(t.a) : textClassifier;
    }

    @NonNull
    public androidx.core.text.c getTextMetricsParamsCompat() {
        return B6.a(this);
    }

    public boolean isEmojiCompatEnabled() {
        return ((AbstractC3099a7) getEmojiTextViewHelper().b.b).d();
    }

    @Override // android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        this.mTextHelper.getClass();
        if (Build.VERSION.SDK_INT < 30 && inputConnectionOnCreateInputConnection != null) {
            AbstractC3307y6.b(editorInfo, getText());
        }
        com.facebook.appevents.i.c(inputConnectionOnCreateInputConnection, editorInfo, this);
        return inputConnectionOnCreateInputConnection;
    }

    @Override // android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        int i = Build.VERSION.SDK_INT;
        if (i < 30 || i >= 33 || !onCheckIsTextEditor()) {
            return;
        }
        ((InputMethodManager) getContext().getSystemService("input_method")).isActive(this);
    }

    @Override // android.widget.TextView, android.view.View
    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        Z z2 = this.mTextHelper;
        if (z2 == null || C1.c) {
            return;
        }
        z2.i.a();
    }

    @Override // android.widget.TextView, android.view.View
    public void onMeasure(int i, int i2) {
        c();
        super.onMeasure(i, i2);
    }

    @Override // android.widget.TextView
    public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        super.onTextChanged(charSequence, i, i2, i3);
        Z z = this.mTextHelper;
        if (z == null || C1.c || !z.i.f()) {
            return;
        }
        this.mTextHelper.i.a();
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z) {
        super.setAllCaps(z);
        getEmojiTextViewHelper().c(z);
    }

    @Override // android.widget.TextView, androidx.core.widget.b
    public void setAutoSizeTextTypeUniformWithConfiguration(int i, int i2, int i3, int i4) throws IllegalArgumentException {
        if (C1.c) {
            super.setAutoSizeTextTypeUniformWithConfiguration(i, i2, i3, i4);
            return;
        }
        Z z = this.mTextHelper;
        if (z != null) {
            z.h(i, i2, i3, i4);
        }
    }

    @Override // android.widget.TextView
    public void setAutoSizeTextTypeUniformWithPresetSizes(@NonNull int[] iArr, int i) throws IllegalArgumentException {
        if (C1.c) {
            super.setAutoSizeTextTypeUniformWithPresetSizes(iArr, i);
            return;
        }
        Z z = this.mTextHelper;
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
        Z z = this.mTextHelper;
        if (z != null) {
            z.j(i);
        }
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            c0105q.e();
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            c0105q.f(i);
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelativeWithIntrinsicBounds(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelativeWithIntrinsicBounds(drawable, drawable2, drawable3, drawable4);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesWithIntrinsicBounds(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesWithIntrinsicBounds(drawable, drawable2, drawable3, drawable4);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
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

    @Override // android.widget.TextView
    public void setFirstBaselineToTopHeight(int i) {
        if (Build.VERSION.SDK_INT >= 28) {
            getSuperCaller().c(i);
        } else {
            B6.b(this, i);
        }
    }

    @Override // android.widget.TextView
    public void setLastBaselineToBottomHeight(int i) {
        if (Build.VERSION.SDK_INT >= 28) {
            getSuperCaller().b(i);
        } else {
            B6.c(this, i);
        }
    }

    @Override // android.widget.TextView
    public void setLineHeight(int i) {
        B6.d(this, i);
    }

    public void setPrecomputedText(@NonNull androidx.core.text.d dVar) {
        if (Build.VERSION.SDK_INT >= 29) {
            throw null;
        }
        B6.a(this);
        throw null;
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            c0105q.h(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0105q c0105q = this.mBackgroundTintHelper;
        if (c0105q != null) {
            c0105q.i(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        this.mTextHelper.k(colorStateList);
        this.mTextHelper.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        this.mTextHelper.l(mode);
        this.mTextHelper.b();
    }

    @Override // android.widget.TextView
    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        Z z = this.mTextHelper;
        if (z != null) {
            z.g(context, i);
        }
    }

    @Override // android.widget.TextView
    public void setTextClassifier(TextClassifier textClassifier) {
        T t;
        if (Build.VERSION.SDK_INT >= 28 || (t = this.mTextClassifierHelper) == null) {
            super.setTextClassifier(textClassifier);
        } else {
            t.b = textClassifier;
        }
    }

    public void setTextFuture(Future<androidx.core.text.d> future) {
        this.mPrecomputedTextFuture = future;
        if (future != null) {
            requestLayout();
        }
    }

    public void setTextMetricsParamsCompat(@NonNull androidx.core.text.c cVar) {
        TextDirectionHeuristic textDirectionHeuristic;
        TextDirectionHeuristic textDirectionHeuristic2 = cVar.b;
        TextDirectionHeuristic textDirectionHeuristic3 = TextDirectionHeuristics.FIRSTSTRONG_RTL;
        int i = 1;
        if (textDirectionHeuristic2 != textDirectionHeuristic3 && textDirectionHeuristic2 != (textDirectionHeuristic = TextDirectionHeuristics.FIRSTSTRONG_LTR)) {
            if (textDirectionHeuristic2 == TextDirectionHeuristics.ANYRTL_LTR) {
                i = 2;
            } else if (textDirectionHeuristic2 == TextDirectionHeuristics.LTR) {
                i = 3;
            } else if (textDirectionHeuristic2 == TextDirectionHeuristics.RTL) {
                i = 4;
            } else if (textDirectionHeuristic2 == TextDirectionHeuristics.LOCALE) {
                i = 5;
            } else if (textDirectionHeuristic2 == textDirectionHeuristic) {
                i = 6;
            } else if (textDirectionHeuristic2 == textDirectionHeuristic3) {
                i = 7;
            }
        }
        setTextDirection(i);
        getPaint().set(cVar.a);
        setBreakStrategy(cVar.c);
        setHyphenationFrequency(cVar.d);
    }

    @Override // android.widget.TextView
    public void setTextSize(int i, float f) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        boolean z = C1.c;
        if (z) {
            super.setTextSize(i, f);
            return;
        }
        Z z2 = this.mTextHelper;
        if (z2 == null || z) {
            return;
        }
        C0088h0 c0088h0 = z2.i;
        if (c0088h0.f()) {
            return;
        }
        c0088h0.g(f, i);
    }

    @Override // android.widget.TextView
    public void setTypeface(Typeface typeface, int i) {
        Typeface typefaceCreate;
        if (this.mIsSetTypefaceProcessing) {
            return;
        }
        if (typeface == null || i <= 0) {
            typefaceCreate = null;
        } else {
            Context context = getContext();
            AbstractC3161h6 abstractC3161h6 = androidx.core.graphics.h.a;
            if (context == null) {
                throw new IllegalArgumentException("Context cannot be null");
            }
            typefaceCreate = Typeface.create(typeface, i);
        }
        this.mIsSetTypefaceProcessing = true;
        if (typefaceCreate != null) {
            typeface = typefaceCreate;
        }
        try {
            super.setTypeface(typeface, i);
        } finally {
            this.mIsSetTypefaceProcessing = false;
        }
    }

    public AppCompatTextView(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.textViewStyle);
    }

    @Override // android.widget.TextView
    public void setLineHeight(int i, float f) {
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 34) {
            getSuperCaller().f(i, f);
        } else if (i2 >= 34) {
            AbstractC0029a.l(this, i, f);
        } else {
            B6.d(this, Math.round(TypedValue.applyDimension(i, f, getResources().getDisplayMetrics())));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AppCompatTextView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        n1.a(context);
        this.mIsSetTypefaceProcessing = false;
        this.mSuperCaller = null;
        m1.a(getContext(), this);
        C0105q c0105q = new C0105q(this);
        this.mBackgroundTintHelper = c0105q;
        c0105q.d(attributeSet, i);
        Z z = new Z(this);
        this.mTextHelper = z;
        z.f(attributeSet, i);
        z.b();
        T t = new T();
        t.a = this;
        this.mTextClassifierHelper = t;
        getEmojiTextViewHelper().b(attributeSet, i);
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelativeWithIntrinsicBounds(int i, int i2, int i3, int i4) {
        Context context = getContext();
        setCompoundDrawablesRelativeWithIntrinsicBounds(i != 0 ? com.facebook.appevents.g.f(context, i) : null, i2 != 0 ? com.facebook.appevents.g.f(context, i2) : null, i3 != 0 ? com.facebook.appevents.g.f(context, i3) : null, i4 != 0 ? com.facebook.appevents.g.f(context, i4) : null);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesWithIntrinsicBounds(int i, int i2, int i3, int i4) {
        Context context = getContext();
        setCompoundDrawablesWithIntrinsicBounds(i != 0 ? com.facebook.appevents.g.f(context, i) : null, i2 != 0 ? com.facebook.appevents.g.f(context, i2) : null, i3 != 0 ? com.facebook.appevents.g.f(context, i3) : null, i4 != 0 ? com.facebook.appevents.g.f(context, i4) : null);
        Z z = this.mTextHelper;
        if (z != null) {
            z.b();
        }
    }
}
