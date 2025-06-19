package com.quizlet.infra.legacysyncengine.datasources;

import java.util.List;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;
    public final /* synthetic */ List c;

    public /* synthetic */ a(b bVar, List list, int i) {
        this.a = i;
        this.b = bVar;
        this.c = list;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.h(this.c);
                break;
            default:
                this.b.h(this.c);
                break;
        }
    }
}
