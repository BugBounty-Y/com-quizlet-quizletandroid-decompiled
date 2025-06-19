package com.google.android.material.textfield;

import android.text.Editable;

/* loaded from: classes2.dex */
public final class j extends com.google.android.material.internal.o {
    public final /* synthetic */ l a;

    public j(l lVar) {
        this.a = lVar;
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable editable) {
        this.a.b().a();
    }

    @Override // com.google.android.material.internal.o, android.text.TextWatcher
    public final void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        this.a.b().b();
    }
}
