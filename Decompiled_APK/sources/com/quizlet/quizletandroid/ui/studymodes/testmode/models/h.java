package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements com.quizlet.baserecyclerview.a {
    public final int a;
    public final Integer b;
    public final Integer c;

    public h(int i, Integer num, Integer num2, int i2) {
        num = (i2 & 2) != 0 ? null : num;
        Intrinsics.checkNotNullParameter("test_mode_motivational_message_id", DBSessionFields.Names.ITEM_ID);
        this.a = i;
        this.b = num;
        this.c = num2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b) && this.c.equals(hVar.c);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "test_mode_motivational_message_id";
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        Integer num = this.b;
        return ((this.c.hashCode() + ((iHashCode + (num == null ? 0 : num.hashCode())) * 31)) * 31) + 158515202;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MotivationalMessageItem(resMessageId=");
        sb.append(this.a);
        sb.append(", resDescriptionId=");
        sb.append(this.b);
        sb.append(", resDrawableId=");
        return assistantMode.refactored.a.l(sb, this.c, ", itemId=test_mode_motivational_message_id)");
    }
}
