package com.braze.communication;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.practicetest.detail.data.F;
import com.quizlet.features.practicetest.detail.data.l;
import com.quizlet.features.universaluploadflow.pastetext.data.n;
import com.quizlet.features.universaluploadflow.pastetext.data.o;
import com.quizlet.features.universaluploadflow.pastetext.data.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ i(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                if (((com.quizlet.features.notes.upload.states.h) this.b) instanceof com.quizlet.features.notes.upload.states.f) {
                    ((InterfaceC0773a0) this.d).setValue(Boolean.TRUE);
                } else if (StringsKt.O((String) ((InterfaceC0773a0) this.e).getValue())) {
                    ((Function0) this.c).invoke();
                } else {
                    ((InterfaceC0773a0) this.f).setValue(Boolean.TRUE);
                }
                break;
            case 2:
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.f;
                boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
                x xVar = (x) this.b;
                if (zBooleanValue) {
                    x.d(xVar);
                    interfaceC0773a0.setValue(Boolean.FALSE);
                } else if (((F) this.c).k) {
                    ((Function1) this.d).invoke(l.a);
                } else {
                    if (xVar.b()) {
                        xVar.a();
                    }
                    x.d((x) this.e);
                }
                break;
            default:
                p pVar = (p) this.b;
                if (pVar instanceof o) {
                    ((InterfaceC0773a0) this.d).setValue(Boolean.TRUE);
                } else if ((pVar instanceof n) || StringsKt.O((String) ((InterfaceC0773a0) this.e).getValue())) {
                    ((Function1) this.c).invoke(com.quizlet.features.universaluploadflow.pastetext.data.a.a);
                } else {
                    ((InterfaceC0773a0) this.f).setValue(Boolean.TRUE);
                }
                break;
        }
        return Unit.a;
    }
}
