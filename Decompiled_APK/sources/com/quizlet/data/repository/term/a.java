package com.quizlet.data.repository.term;

import com.braze.requests.framework.k;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.quizlet.assembly.compose.listitems.r;
import io.reactivex.rxjava3.functions.j;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ g a;
    public final /* synthetic */ long b;
    public final /* synthetic */ int c;

    public /* synthetic */ a(g gVar, long j, int i) {
        this.a = gVar;
        this.b = j;
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        g gVar = this.a;
        return AbstractC3738u6.b(gVar.c, new k(this.c, 1, this.b, gVar), new r(17));
    }
}
