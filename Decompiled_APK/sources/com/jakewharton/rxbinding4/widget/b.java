package com.jakewharton.rxbinding4.widget;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import io.reactivex.rxjava3.core.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends io.reactivex.rxjava3.android.a implements TextWatcher {
    public final /* synthetic */ int b = 1;
    public final l c;
    public final EditText d;

    public b(EditText view, l observer) {
        Intrinsics.f(view, "view");
        Intrinsics.f(observer, "observer");
        this.d = view;
        this.c = observer;
    }

    @Override // io.reactivex.rxjava3.android.a
    public final void a() {
        switch (this.b) {
            case 0:
                ((AssemblyInputEditText) this.d).removeTextChangedListener(this);
                break;
            default:
                this.d.removeTextChangedListener(this);
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        switch (this.b) {
            case 0:
                Intrinsics.f(s, "s");
                this.c.b(new a((AssemblyInputEditText) this.d, s));
                break;
            default:
                Intrinsics.f(s, "s");
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        switch (this.b) {
            case 0:
                Intrinsics.f(charSequence, "charSequence");
                break;
            default:
                Intrinsics.f(charSequence, "s");
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        switch (this.b) {
            case 0:
                Intrinsics.f(charSequence, "charSequence");
                break;
            default:
                Intrinsics.f(charSequence, "s");
                if (!this.a.get()) {
                    this.c.b(charSequence);
                    break;
                }
                break;
        }
    }

    public b(AssemblyInputEditText assemblyInputEditText, l observer) {
        Intrinsics.f(observer, "observer");
        this.d = assemblyInputEditText;
        this.c = observer;
    }
}
