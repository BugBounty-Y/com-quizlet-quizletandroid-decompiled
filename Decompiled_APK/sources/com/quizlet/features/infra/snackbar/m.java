package com.quizlet.features.infra.snackbar;

import android.content.Context;
import android.widget.Toast;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends a {
    public final com.quizlet.qutils.string.g a;

    public m(com.quizlet.qutils.string.g gVar) {
        this.a = gVar;
    }

    public final void a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String strA = this.a.a(context);
        if (strA == null) {
            strA = "";
        }
        Toast.makeText(context, strA, 1).show();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof m) {
            return this.a.equals(((m) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }

    public final String toString() {
        return "ShowToastData(stringResData=" + this.a + ", msg=null)";
    }
}
