package com.quizlet.infra.legacysyncengine.datasources;

import java.util.ArrayList;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements com.quizlet.infra.legacysyncengine.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ j(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // com.quizlet.infra.legacysyncengine.a
    public final void a(ArrayList arrayList) {
        switch (this.a) {
            case 0:
                this.b.invoke(arrayList);
                break;
            default:
                this.b.invoke(arrayList);
                break;
        }
    }
}
