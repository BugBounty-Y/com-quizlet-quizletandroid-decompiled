package androidx.appcompat.widget;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.method.KeyListener;
import android.text.method.NumberKeyListener;
import android.util.AttributeSet;
import android.util.Log;
import android.view.ActionMode;
import android.view.DragEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.view.textclassifier.TextClassifier;
import android.widget.EditText;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.C0132i;
import androidx.core.view.C1046f;
import androidx.core.view.C1050h;
import androidx.core.view.InterfaceC1044e;
import androidx.core.view.InterfaceC1063u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.quizlet.quizletandroid.R;

/* renamed from: androidx.appcompat.widget.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0116w extends EditText implements InterfaceC1063u {
    public final C0105q a;
    public final Z b;
    public final T c;
    public final androidx.core.widget.p d;
    public final C e;
    public C0114v f;

    public C0116w(@NonNull Context context) {
        this(context, null);
    }

    @NonNull
    private C0114v getSuperCaller() {
        if (this.f == null) {
            this.f = new C0114v(this);
        }
        return this.f;
    }

    @Override // androidx.core.view.InterfaceC1063u
    public final C1050h a(C1050h c1050h) {
        this.d.getClass();
        return androidx.core.widget.p.a(this, c1050h);
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

    @Override // android.widget.TextView
    @NonNull
    public TextClassifier getTextClassifier() {
        T t;
        if (Build.VERSION.SDK_INT >= 28 || (t = this.c) == null) {
            return super.getTextClassifier();
        }
        TextClassifier textClassifier = t.b;
        return textClassifier == null ? S.a(t.a) : textClassifier;
    }

    @Override // android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        String[] strArrG;
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        this.b.getClass();
        int i = Build.VERSION.SDK_INT;
        if (i < 30 && inputConnectionOnCreateInputConnection != null) {
            AbstractC3307y6.b(editorInfo, getText());
        }
        com.facebook.appevents.i.c(inputConnectionOnCreateInputConnection, editorInfo, this);
        if (inputConnectionOnCreateInputConnection != null && i <= 30 && (strArrG = androidx.core.view.V.g(this)) != null) {
            editorInfo.contentMimeTypes = strArrG;
            inputConnectionOnCreateInputConnection = new androidx.core.view.inputmethod.b(inputConnectionOnCreateInputConnection, new C0132i(this, 15));
        }
        return this.e.c(inputConnectionOnCreateInputConnection, editorInfo);
    }

    @Override // android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        int i = Build.VERSION.SDK_INT;
        if (i < 30 || i >= 33) {
            return;
        }
        ((InputMethodManager) getContext().getSystemService("input_method")).isActive(this);
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onDragEvent(DragEvent dragEvent) {
        Activity activity;
        boolean zA = false;
        if (Build.VERSION.SDK_INT < 31 && dragEvent.getLocalState() == null && androidx.core.view.V.g(this) != null) {
            Context context = getContext();
            while (true) {
                if (!(context instanceof ContextWrapper)) {
                    activity = null;
                    break;
                }
                if (context instanceof Activity) {
                    activity = (Activity) context;
                    break;
                }
                context = ((ContextWrapper) context).getBaseContext();
            }
            if (activity == null) {
                Log.i("ReceiveContent", "Can't handle drop: no activity: view=" + this);
            } else if (dragEvent.getAction() != 1 && dragEvent.getAction() == 3) {
                zA = F.a(dragEvent, this, activity);
            }
        }
        if (zA) {
            return true;
        }
        return super.onDragEvent(dragEvent);
    }

    @Override // android.widget.EditText, android.widget.TextView
    public boolean onTextContextMenuItem(int i) {
        InterfaceC1044e hVar;
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 31 || androidx.core.view.V.g(this) == null || !(i == 16908322 || i == 16908337)) {
            return super.onTextContextMenuItem(i);
        }
        ClipboardManager clipboardManager = (ClipboardManager) getContext().getSystemService("clipboard");
        ClipData primaryClip = clipboardManager == null ? null : clipboardManager.getPrimaryClip();
        if (primaryClip != null && primaryClip.getItemCount() > 0) {
            if (i2 >= 31) {
                hVar = new com.google.android.gms.auth.api.signin.internal.h(primaryClip, 1);
            } else {
                C1046f c1046f = new C1046f();
                c1046f.b = primaryClip;
                c1046f.c = 1;
                hVar = c1046f;
            }
            hVar.r(i == 16908322 ? 0 : 1);
            androidx.core.view.V.k(this, hVar.build());
        }
        return true;
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
    public final void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        Z z = this.b;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        Z z = this.b;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(B6.i(callback, this));
    }

    public void setEmojiCompatEnabled(boolean z) {
        this.e.d(z);
    }

    @Override // android.widget.TextView
    public void setKeyListener(KeyListener keyListener) {
        super.setKeyListener(this.e.a(keyListener));
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
    public void setTextClassifier(TextClassifier textClassifier) {
        T t;
        if (Build.VERSION.SDK_INT >= 28 || (t = this.c) == null) {
            super.setTextClassifier(textClassifier);
        } else {
            t.b = textClassifier;
        }
    }

    public C0116w(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.editTextStyle);
    }

    @Override // android.widget.EditText, android.widget.TextView
    public Editable getText() {
        return Build.VERSION.SDK_INT >= 28 ? super.getText() : super.getEditableText();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0116w(Context context, AttributeSet attributeSet, int i) {
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
        T t = new T();
        t.a = this;
        this.c = t;
        this.d = new androidx.core.widget.p();
        C c = new C(this);
        this.e = c;
        c.b(attributeSet, i);
        KeyListener keyListener = getKeyListener();
        if (keyListener instanceof NumberKeyListener) {
            return;
        }
        boolean zIsFocusable = super.isFocusable();
        boolean zIsClickable = super.isClickable();
        boolean zIsLongClickable = super.isLongClickable();
        int inputType = super.getInputType();
        KeyListener keyListenerA = c.a(keyListener);
        if (keyListenerA == keyListener) {
            return;
        }
        super.setKeyListener(keyListenerA);
        super.setRawInputType(inputType);
        super.setFocusable(zIsFocusable);
        super.setClickable(zIsClickable);
        super.setLongClickable(zIsLongClickable);
    }
}
