package com.jakewharton.rxbinding4.widget;

import android.text.Editable;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final AssemblyInputEditText a;
    public final Editable b;

    public a(AssemblyInputEditText view, Editable editable) {
        Intrinsics.f(view, "view");
        this.a = view;
        this.b = editable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        AssemblyInputEditText assemblyInputEditText = this.a;
        int iHashCode = (assemblyInputEditText != null ? assemblyInputEditText.hashCode() : 0) * 31;
        Editable editable = this.b;
        return iHashCode + (editable != null ? editable.hashCode() : 0);
    }

    public final String toString() {
        return "TextViewAfterTextChangeEvent(view=" + this.a + ", editable=" + ((Object) this.b) + ")";
    }
}
