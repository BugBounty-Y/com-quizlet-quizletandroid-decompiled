package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.o2;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements com.quizlet.baserecyclerview.a {
    public final InterfaceC4176w0 a;
    public final o2 b;

    public y(InterfaceC4176w0 testMeteredEvent, o2 learnMeteredEvent) {
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        Intrinsics.checkNotNullParameter("upgrade_event_id", DBSessionFields.Names.ITEM_ID);
        this.a = testMeteredEvent;
        this.b = learnMeteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.a, yVar.a) && this.b.equals(yVar.b);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "upgrade_event_id";
    }

    public final int hashCode() {
        return ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31) + 148240291;
    }

    public final String toString() {
        return "UpgradeEvent(testMeteredEvent=" + this.a + ", learnMeteredEvent=" + this.b + ", itemId=upgrade_event_id)";
    }
}
