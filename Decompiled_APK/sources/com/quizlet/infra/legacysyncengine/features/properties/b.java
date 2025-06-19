package com.quizlet.infra.legacysyncengine.features.properties;

import com.quizlet.infra.legacysyncengine.datasources.f;
import com.quizlet.infra.legacysyncengine.datasources.q;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements io.reactivex.rxjava3.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ com.quizlet.infra.legacysyncengine.orm.query.a c;
    public final /* synthetic */ com.quizlet.infra.legacysyncengine.a d;

    public /* synthetic */ b(Object obj, com.quizlet.infra.legacysyncengine.orm.query.a aVar, com.quizlet.infra.legacysyncengine.a aVar2, int i) {
        this.a = i;
        this.b = obj;
        this.c = aVar;
        this.d = aVar2;
    }

    @Override // io.reactivex.rxjava3.functions.c
    public final void cancel() {
        switch (this.a) {
            case 0:
                ((d) this.b).a.a(this.c, (q) this.d);
                break;
            case 1:
                ((d) this.b).a.a(this.c, (q) this.d);
                break;
            case 2:
                ((com.quizlet.infra.legacysyncengine.net.c) this.b).a(this.c, (q) this.d);
                break;
            case 3:
                ((com.quizlet.infra.legacysyncengine.net.c) this.b).a(this.c, (f) this.d);
                break;
            case 4:
                com.onetrust.otpublishers.headless.UI.fragment.q qVar = (com.onetrust.otpublishers.headless.UI.fragment.q) this.b;
                ((com.quizlet.infra.legacysyncengine.net.c) qVar.b).a(this.c, (q) this.d);
                break;
            default:
                com.onetrust.otpublishers.headless.UI.fragment.q qVar2 = (com.onetrust.otpublishers.headless.UI.fragment.q) this.b;
                ((com.quizlet.infra.legacysyncengine.net.c) qVar2.b).a(this.c, (q) this.d);
                break;
        }
    }
}
