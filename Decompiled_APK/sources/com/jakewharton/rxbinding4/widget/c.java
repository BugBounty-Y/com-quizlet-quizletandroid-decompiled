package com.jakewharton.rxbinding4.widget;

import android.widget.EditText;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends i {
    public final /* synthetic */ int a = 1;
    public final EditText b;

    public c(EditText view) {
        Intrinsics.f(view, "view");
        this.b = view;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(l observer) {
        Object aVar;
        Intrinsics.f(observer, "observer");
        z(observer);
        switch (this.a) {
            case 0:
                AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) this.b;
                aVar = new a(assemblyInputEditText, assemblyInputEditText.getEditableText());
                break;
            default:
                aVar = this.b.getText();
                break;
        }
        observer.b(aVar);
    }

    public final void z(l observer) {
        switch (this.a) {
            case 0:
                Intrinsics.f(observer, "observer");
                AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) this.b;
                b bVar = new b(assemblyInputEditText, observer);
                observer.a(bVar);
                assemblyInputEditText.addTextChangedListener(bVar);
                break;
            default:
                Intrinsics.f(observer, "observer");
                EditText editText = this.b;
                b bVar2 = new b(editText, observer);
                observer.a(bVar2);
                editText.addTextChangedListener(bVar2);
                break;
        }
    }

    public c(AssemblyInputEditText assemblyInputEditText) {
        this.b = assemblyInputEditText;
    }
}
