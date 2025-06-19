package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements com.quizlet.baserecyclerview.a {
    public final com.quizlet.uicommon.ui.common.util.d a;
    public final com.quizlet.uicommon.ui.common.util.d b;
    public final Function1 c;
    public final Function1 d;

    public i(com.quizlet.uicommon.ui.common.util.d primaryStepData, com.quizlet.uicommon.ui.common.util.d secondaryStepData, Function1 primaryStepClick, Function1 secondaryStepClick) {
        Intrinsics.checkNotNullParameter(primaryStepData, "primaryStepData");
        Intrinsics.checkNotNullParameter(secondaryStepData, "secondaryStepData");
        Intrinsics.checkNotNullParameter(primaryStepClick, "primaryStepClick");
        Intrinsics.checkNotNullParameter(secondaryStepClick, "secondaryStepClick");
        Intrinsics.checkNotNullParameter("test_mode_next_step_id", DBSessionFields.Names.ITEM_ID);
        this.a = primaryStepData;
        this.b = secondaryStepData;
        this.c = primaryStepClick;
        this.d = secondaryStepClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b.equals(iVar.b) && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(this.d, iVar.d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "test_mode_next_step_id";
    }

    public final int hashCode() {
        return ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31) - 686484271;
    }

    public final String toString() {
        return "NextStepItem(primaryStepData=" + this.a + ", secondaryStepData=" + this.b + ", primaryStepClick=" + this.c + ", secondaryStepClick=" + this.d + ", itemId=test_mode_next_step_id)";
    }
}
