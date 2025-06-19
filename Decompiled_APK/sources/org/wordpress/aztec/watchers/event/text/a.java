package org.wordpress.aztec.watchers.event.text;

import android.text.Editable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Editable a;

    public a(Editable editable) {
        this.a = editable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        Editable editable = this.a;
        if (editable == null) {
            return 0;
        }
        return editable.hashCode();
    }

    public final String toString() {
        return "AfterTextChangedEventData(textAfter=" + ((Object) this.a) + ')';
    }
}
