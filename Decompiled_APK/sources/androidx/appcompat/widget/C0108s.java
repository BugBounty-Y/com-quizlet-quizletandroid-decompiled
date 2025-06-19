package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.CheckedTextView;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.quizlet.quizletandroid.R;

/* renamed from: androidx.appcompat.widget.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0108s extends CheckedTextView {
    public final C0110t a;
    public final C0105q b;
    public final Z c;
    public C0118x d;

    public C0108s(@NonNull Context context) {
        this(context, null);
    }

    @NonNull
    private C0118x getEmojiTextViewHelper() {
        if (this.d == null) {
            this.d = new C0118x(this);
        }
        return this.d;
    }

    @Override // android.widget.CheckedTextView, android.widget.TextView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        Z z = this.c;
        if (z != null) {
            z.b();
        }
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.a();
        }
        C0110t c0110t = this.a;
        if (c0110t != null) {
            c0110t.b();
        }
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return B6.h(super.getCustomSelectionActionModeCallback());
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            return c0105q.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            return c0105q.c();
        }
        return null;
    }

    public ColorStateList getSupportCheckMarkTintList() {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            return (ColorStateList) c0110t.a;
        }
        return null;
    }

    public PorterDuff.Mode getSupportCheckMarkTintMode() {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            return (PorterDuff.Mode) c0110t.b;
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.c.d();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.c.e();
    }

    @Override // android.widget.TextView, android.view.View
    public final InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        com.facebook.appevents.i.c(inputConnectionOnCreateInputConnection, editorInfo, this);
        return inputConnectionOnCreateInputConnection;
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z) {
        super.setAllCaps(z);
        getEmojiTextViewHelper().c(z);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.e();
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.f(i);
        }
    }

    @Override // android.widget.CheckedTextView
    public void setCheckMarkDrawable(Drawable drawable) {
        super.setCheckMarkDrawable(drawable);
        C0110t c0110t = this.a;
        if (c0110t != null) {
            if (c0110t.e) {
                c0110t.e = false;
            } else {
                c0110t.e = true;
                c0110t.b();
            }
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        Z z = this.c;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        Z z = this.c;
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

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.h(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.i(mode);
        }
    }

    public void setSupportCheckMarkTintList(ColorStateList colorStateList) {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            c0110t.a = colorStateList;
            c0110t.c = true;
            c0110t.b();
        }
    }

    public void setSupportCheckMarkTintMode(PorterDuff.Mode mode) {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            c0110t.b = mode;
            c0110t.d = true;
            c0110t.b();
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        Z z = this.c;
        z.k(colorStateList);
        z.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        Z z = this.c;
        z.l(mode);
        z.b();
    }

    @Override // android.widget.TextView
    public final void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        Z z = this.c;
        if (z != null) {
            z.g(context, i);
        }
    }

    public C0108s(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.checkedTextViewStyle);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0108s(Context context, AttributeSet attributeSet, int i) {
        int resourceId;
        int resourceId2;
        super(context, attributeSet, i);
        n1.a(context);
        m1.a(getContext(), this);
        Z z = new Z(this);
        this.c = z;
        z.f(attributeSet, i);
        z.b();
        C0105q c0105q = new C0105q(this);
        this.b = c0105q;
        c0105q.d(attributeSet, i);
        this.a = new C0110t(this);
        Context context2 = getContext();
        int[] iArr = androidx.appcompat.a.l;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context2, attributeSet, iArr, i);
        TypedArray typedArray = (TypedArray) eVarM.c;
        androidx.core.view.V.n(this, getContext(), iArr, attributeSet, (TypedArray) eVarM.c, i);
        try {
            if (typedArray.hasValue(1) && (resourceId2 = typedArray.getResourceId(1, 0)) != 0) {
                try {
                    setCheckMarkDrawable(com.facebook.appevents.g.f(getContext(), resourceId2));
                } catch (Resources.NotFoundException unused) {
                }
            } else if (typedArray.hasValue(0) && (resourceId = typedArray.getResourceId(0, 0)) != 0) {
                setCheckMarkDrawable(com.facebook.appevents.g.f(getContext(), resourceId));
            }
            if (typedArray.hasValue(2)) {
                setCheckMarkTintList(eVarM.e(2));
            }
            if (typedArray.hasValue(3)) {
                setCheckMarkTintMode(AbstractC0102o0.c(typedArray.getInt(3, -1), null));
            }
            eVarM.n();
            getEmojiTextViewHelper().b(attributeSet, i);
        } catch (Throwable th) {
            eVarM.n();
            throw th;
        }
    }

    @Override // android.widget.CheckedTextView
    public void setCheckMarkDrawable(int i) {
        setCheckMarkDrawable(com.facebook.appevents.g.f(getContext(), i));
    }
}
