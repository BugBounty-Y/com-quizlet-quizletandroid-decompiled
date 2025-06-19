package com.quizlet.quizletandroid.ui.studymodes.write;

import com.quizlet.db.data.models.persisted.DBTerm;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.C4977c0;
import kotlinx.coroutines.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements com.quizlet.qutils.rx.b, io.reactivex.rxjava3.core.j {
    public final /* synthetic */ Object a;
    public final /* synthetic */ Object b;

    public /* synthetic */ g(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.j
    public void l(C4899s c4899s) {
        c4899s.d(new kotlinx.coroutines.rx3.e(E.z(C4977c0.a, O.b.plus((CoroutineContext) this.a), D.c, new kotlinx.coroutines.rx3.h((InterfaceC4992i) this.b, c4899s, null))));
    }

    @Override // com.quizlet.qutils.rx.b
    public void run() {
        WriteModePromptView.a((WriteModePromptView) this.a, (DBTerm) this.b);
    }
}
