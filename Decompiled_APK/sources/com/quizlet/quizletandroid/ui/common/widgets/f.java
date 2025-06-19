package com.quizlet.quizletandroid.ui.common.widgets;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.k;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.l;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.m;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements View.OnFocusChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ f(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        switch (this.a) {
            case 0:
                QRichFormField.l((QRichFormField) this.b, (QRichTextToolbar) this.c, view, z);
                break;
            default:
                m mVar = (m) this.b;
                if (mVar.g) {
                    l lVar = (l) this.c;
                    lVar.e = z;
                    if (!z) {
                        lVar.c(null);
                        if (lVar.d != null) {
                            lVar.b();
                        }
                    }
                    boolean z2 = lVar.c;
                    O1 o1 = z2 ? O1.WORD : O1.DEFINITION;
                    int adapterPosition = mVar.getAdapterPosition();
                    if (lVar.e) {
                        Looper looperMyLooper = Looper.myLooper();
                        if (looperMyLooper == null) {
                            looperMyLooper = Looper.getMainLooper();
                        }
                        new Handler(looperMyLooper).post(new com.google.android.datatransport.runtime.scheduling.jobscheduling.e(adapterPosition, 1, lVar, mVar, o1));
                    }
                    if (!z2) {
                        m mVar2 = lVar.k;
                        lVar.h.u().i(new k(mVar2, z, mVar2.f), io.reactivex.rxjava3.internal.functions.d.e);
                        break;
                    }
                }
                break;
        }
    }
}
