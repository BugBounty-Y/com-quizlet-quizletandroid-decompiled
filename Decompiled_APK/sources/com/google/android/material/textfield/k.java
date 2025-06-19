package com.google.android.material.textfield;

import android.widget.EditText;

/* loaded from: classes2.dex */
public final class k {
    public final /* synthetic */ l a;

    public k(l lVar) {
        this.a = lVar;
    }

    public final void a(TextInputLayout textInputLayout) {
        l lVar = this.a;
        if (lVar.s == textInputLayout.getEditText()) {
            return;
        }
        EditText editText = lVar.s;
        j jVar = lVar.v;
        if (editText != null) {
            editText.removeTextChangedListener(jVar);
            if (lVar.s.getOnFocusChangeListener() == lVar.b().e()) {
                lVar.s.setOnFocusChangeListener(null);
            }
        }
        EditText editText2 = textInputLayout.getEditText();
        lVar.s = editText2;
        if (editText2 != null) {
            editText2.addTextChangedListener(jVar);
        }
        lVar.b().m(lVar.s);
        lVar.j(lVar.b());
    }
}
