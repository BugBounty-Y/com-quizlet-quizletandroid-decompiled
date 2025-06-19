package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements com.quizlet.baserecyclerview.a {
    public final int a;
    public final int b;
    public final int c;

    public z(int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter("test_mode_your_results_id", DBSessionFields.Names.ITEM_ID);
        this.a = i;
        this.b = i2;
        this.c = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return this.a == zVar.a && this.b == zVar.b && this.c == zVar.c;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "test_mode_your_results_id";
    }

    public final int hashCode() {
        return ((Integer.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31)) * 31) + 1539469441;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("YourResultsItem(progress=");
        sb.append(this.a);
        sb.append(", correctCount=");
        sb.append(this.b);
        sb.append(", incorrectCount=");
        return android.support.v4.media.session.a.r(sb, this.c, ", itemId=test_mode_your_results_id)");
    }
}
