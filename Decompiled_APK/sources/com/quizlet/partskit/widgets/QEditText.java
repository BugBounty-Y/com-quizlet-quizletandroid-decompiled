package com.quizlet.partskit.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import androidx.appcompat.widget.C0116w;
import androidx.core.content.res.k;
import com.quizlet.login.recovery.forgotpassword.ui.b;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.u;
import com.quizlet.ui.resources.designsystem.generated.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QEditText extends C0116w {
    public static final /* synthetic */ int j = 0;
    public CharSequence g;
    public final boolean h;
    public final InputMethodManager i;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QEditText(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        try {
            if (isEnabled()) {
                setEnabled(false);
                setEnabled(true);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override // androidx.appcompat.widget.C0116w, android.widget.TextView, android.view.View
    public final InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        Intrinsics.checkNotNullParameter(outAttrs, "outAttrs");
        if (this.i.isFullscreenMode() && this.g != null && getHint() == null) {
            setHint(this.g);
        }
        return super.onCreateInputConnection(outAttrs);
    }

    @Override // android.widget.TextView, android.view.View
    public final void onFocusChanged(boolean z, int i, Rect rect) {
        super.onFocusChanged(z, i, rect);
        if (z || !this.i.isFullscreenMode() || this.g == null || getHint() != null) {
            return;
        }
        setHint((CharSequence) null);
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        Intrinsics.checkNotNullParameter(info, "info");
        super.onInitializeAccessibilityNodeInfo(info);
        CharSequence charSequence = this.g;
        if (charSequence != null && !StringsKt.O(charSequence)) {
            info.setText(((Object) this.g) + " " + ((Object) getText()));
            info.setContentDescription(this.g);
        }
        info.setClickable(true);
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onKeyPreIme(int i, KeyEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event.getKeyCode() == 4 && this.h) {
            clearFocus();
        }
        return super.onKeyPreIme(i, event);
    }

    @Override // android.view.View
    public final void onPopulateAccessibilityEvent(AccessibilityEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        super.onPopulateAccessibilityEvent(event);
        CharSequence charSequence = this.g;
        if (charSequence == null || charSequence == null || StringsKt.O(charSequence)) {
            return;
        }
        event.setContentDescription(this.g);
    }

    public final void setAccessibilityLabel(CharSequence charSequence) {
        this.g = charSequence;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QEditText(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QEditText(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, R.attr.editTextStyle);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.d);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, a.b);
        int i2 = typedArrayObtainStyledAttributes.getInt(0, 0);
        this.h = typedArrayObtainStyledAttributes.getBoolean(2, false);
        typedArrayObtainStyledAttributes.recycle();
        Object systemService = context.getSystemService("input_method");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
        this.i = (InputMethodManager) systemService;
        setOnEditorActionListener(new b(this, 1));
        if (isInEditMode()) {
            return;
        }
        setTypeface(k.a(context, resourceId), i2);
    }
}
