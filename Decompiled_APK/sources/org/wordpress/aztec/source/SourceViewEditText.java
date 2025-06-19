package org.wordpress.aztec.source;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import androidx.appcompat.widget.C0116w;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.H;
import org.wordpress.aztec.m;
import org.wordpress.aztec.z;

@Metadata
@SuppressLint({"SupportAnnotationUsage"})
/* loaded from: classes3.dex */
public class SourceViewEditText extends C0116w implements TextWatcher {
    public int g;
    public int h;
    public c i;
    public boolean j;
    public z k;
    public boolean l;
    public final androidx.camera.camera2.internal.concurrent.a m;
    public byte[] n;

    @Metadata
    public static final class SavedState extends View.BaseSavedState {

        @NotNull
        public static final Parcelable.Creator<SavedState> CREATOR = new d();
        public Bundle a;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel out, int i) {
            Intrinsics.checkNotNullParameter(out, "out");
            super.writeToParcel(out, i);
            out.writeBundle(this.a);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SourceViewEditText(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.g = getContext().getColor(R.color.html_tag);
        this.h = getContext().getColor(R.color.html_attribute);
        this.j = true;
        this.l = true;
        this.m = new androidx.camera.camera2.internal.concurrent.a(this);
        this.n = new byte[0];
        c(null);
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable editable) {
        if (this.l) {
            this.l = false;
            return;
        }
        c cVar = this.i;
        if (cVar != null) {
            cVar.afterTextChanged(editable);
        }
    }

    public final String b() {
        return J2.d(String.valueOf(getText()), this.j, false);
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        z zVar;
        Intrinsics.checkNotNullParameter(text, "text");
        if (!this.l && (zVar = this.k) != null) {
            zVar.a(this);
        }
        c cVar = this.i;
        if (cVar != null) {
            cVar.beforeTextChanged(text, i, i2, i3);
        }
    }

    public final void c(AttributeSet attributeSet) {
        TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, H.b);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        setBackgroundColor(typedArrayObtainStyledAttributes.getColor(1, getContext().getColor(android.R.color.transparent)));
        if (!typedArrayObtainStyledAttributes.hasValue(2) && typedArrayObtainStyledAttributes.getBoolean(2, false)) {
            setTextColor(typedArrayObtainStyledAttributes.getColor(3, android.R.attr.textColorPrimary));
        }
        this.g = typedArrayObtainStyledAttributes.getColor(4, this.g);
        int color = typedArrayObtainStyledAttributes.getColor(0, this.h);
        this.h = color;
        this.i = new c(this.g, color);
        typedArrayObtainStyledAttributes.recycle();
    }

    @Override // android.view.View
    public final boolean dispatchHoverEvent(MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (this.m.H(event)) {
            return true;
        }
        return super.dispatchHoverEvent(event);
    }

    public final int getAttributeColor() {
        return this.h;
    }

    @Override // android.widget.EditText, android.widget.TextView
    public boolean getFreezesText() {
        return false;
    }

    public final z getHistory() {
        return this.k;
    }

    public final int getTagColor() {
        return this.g;
    }

    @Override // android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        addTextChangedListener(this);
    }

    @Override // androidx.appcompat.widget.C0116w, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeTextChangedListener(this);
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onKeyPreIme(int i, KeyEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event.getKeyCode() == 4) {
            event.getAction();
        }
        return super.onKeyPreIme(i, event);
    }

    @Override // android.widget.TextView, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        Intrinsics.e(parcelable, "null cannot be cast to non-null type org.wordpress.aztec.source.SourceViewEditText.SavedState");
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        Bundle bundle = savedState.a;
        setVisibility(bundle.getInt("visibility"));
        setText((String) org.wordpress.aztec.util.b.g("RETAINED_CONTENT_KEY", "", savedState.a));
        EnumC5145a enumC5145a = AztecText.q1;
        byte[] byteArray = bundle.getByteArray("RETAINED_INITIAL_HTML_PARSED_SHA256_KEY");
        if (byteArray != null) {
            this.n = byteArray;
        }
    }

    @Override // android.widget.TextView, android.view.View
    public final Parcelable onSaveInstanceState() throws IOException {
        SavedState savedState;
        Bundle bundle = new Bundle();
        EnumC5145a enumC5145a = AztecText.q1;
        bundle.putByteArray("RETAINED_INITIAL_HTML_PARSED_SHA256_KEY", this.n);
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        org.wordpress.aztec.util.b.h(context, "RETAINED_CONTENT_KEY", String.valueOf(getText()), bundle);
        Parcelable superState = super.onSaveInstanceState();
        if (superState != null) {
            Intrinsics.checkNotNullParameter(superState, "superState");
            savedState = new SavedState(superState);
            savedState.a = new Bundle();
        } else {
            savedState = null;
        }
        bundle.putInt("visibility", getVisibility());
        if (savedState == null) {
            return savedState;
        }
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        savedState.a = bundle;
        return savedState;
    }

    @Override // android.widget.TextView, android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
        c cVar = this.i;
        if (cVar != null) {
            cVar.onTextChanged(text, i, i2, i3);
        }
    }

    public final void setAttributeColor$aztec_release(int i) {
        this.h = i;
    }

    public final void setCalypsoMode(boolean z) {
        this.j = z;
    }

    public final void setHistory(z zVar) {
        this.k = zVar;
    }

    public final void setOnImeBackListener(@NotNull m listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setTagColor$aztec_release(int i) {
        this.g = i;
    }

    @Override // android.view.View
    public void setVisibility(int i) {
        int selectionStart = getSelectionStart();
        super.setVisibility(i);
        if (i == 0) {
            requestFocus();
            if (selectionStart != getSelectionStart()) {
                setSelection(0);
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SourceViewEditText(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        this.g = getContext().getColor(R.color.html_tag);
        this.h = getContext().getColor(R.color.html_attribute);
        this.j = true;
        this.l = true;
        this.m = new androidx.camera.camera2.internal.concurrent.a(this);
        this.n = new byte[0];
        c(attrs);
    }
}
