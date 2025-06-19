package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import androidx.appcompat.app.K;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ m a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;

    public k(m mVar, boolean z, boolean z2) {
        this.a = mVar;
        this.b = z;
        this.c = z2;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Boolean isUnderAge = (Boolean) obj;
        Intrinsics.checkNotNullParameter(isUnderAge, "isUnderAge");
        l lVar = this.a.c;
        boolean z = this.b && this.c && !isUnderAge.booleanValue();
        QRichFormField qRichFormField = lVar.f;
        if (qRichFormField != null) {
            C4636c mOnClickAction = new C4636c(lVar, 2);
            Intrinsics.checkNotNullParameter(mOnClickAction, "mOnClickAction");
            K k = new K();
            k.a = z;
            k.b = mOnClickAction;
            qRichFormField.setFormFieldIcon(k);
        }
    }
}
