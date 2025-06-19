package com.quizlet.infra.legacysyncengine.tasks.read;

import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.j;
import java.sql.SQLException;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;

    public /* synthetic */ a(b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        switch (this.a) {
            case 0:
                b bVar = this.b;
                bVar.getClass();
                try {
                    return p.f(bVar.d(bVar.b));
                } catch (SQLException e) {
                    return p.d(e);
                }
            default:
                b bVar2 = this.b;
                bVar2.getClass();
                try {
                    return i.o(bVar2.d(bVar2.b));
                } catch (SQLException e2) {
                    return i.k(e2);
                }
        }
    }
}
