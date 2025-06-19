package com.quizlet.uicommon.ui.common.widgets;

import android.view.View;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.l;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.m;
import java.lang.ref.WeakReference;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ QFormField b;

    public /* synthetic */ a(QFormField qFormField, int i) {
        this.a = i;
        this.b = qFormField;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        QFormField qFormField = this.b;
        switch (this.a) {
            case 0:
                QFormField.b(qFormField);
                break;
            case 1:
                d dVar = qFormField.p;
                if (dVar != null) {
                    com.quizlet.data.repository.qclass.c cVar = (com.quizlet.data.repository.qclass.c) dVar;
                    m mVar = (m) cVar.c;
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                    mVar.getAdapterPosition();
                    boolean z = ((l) cVar.b).c;
                    com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                    if (aVar != null) {
                        O1 o1 = z ? O1.WORD : O1.DEFINITION;
                        WeakReference weakReference = ((EditSetFragment) aVar).x;
                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar = weakReference != null ? (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get() : null;
                        if (bVar != null) {
                            com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar;
                            dVar2.x(dVar2.y.o.i(new com.quizlet.infra.legacysyncengine.managers.a(2, dVar2, o1), io.reactivex.rxjava3.internal.functions.d.e));
                            break;
                        }
                    }
                }
                break;
            default:
                int[] iArr = QFormField.u;
                if (qFormField.getEditText().isFocusable()) {
                    qFormField.getEditText().requestFocus();
                    break;
                }
                break;
        }
    }
}
