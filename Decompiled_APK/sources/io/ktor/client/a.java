package io.ktor.client;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ c b;

    public /* synthetic */ a(c cVar) {
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Throwable th = (Throwable) obj;
        switch (this.a) {
            case 0:
                if (th != null) {
                    E.i(this.b.a, null);
                }
                break;
            default:
                if (th != null) {
                    this.b.j.i(io.ktor.client.utils.a.e);
                }
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(c cVar, io.ktor.client.statement.b bVar) {
        this.b = cVar;
    }
}
