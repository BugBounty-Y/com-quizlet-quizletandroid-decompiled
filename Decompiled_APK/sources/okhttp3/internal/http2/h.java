package okhttp3.internal.http2;

import com.quizlet.features.folders.composables.W;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes3.dex */
public final class h extends okhttp3.internal.concurrent.a {
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(int i, Object obj, Object obj2, String str) {
        super(str, true);
        this.e = i;
        this.f = obj;
        this.g = obj2;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() {
        long jA;
        v[] vVarArr;
        int i = 0;
        switch (this.e) {
            case 0:
                n nVar = (n) this.f;
                nVar.a.a(nVar, (z) ((J) this.g).a);
                return -1L;
            case 1:
                try {
                    ((n) this.f).a.b((v) this.g);
                } catch (IOException e) {
                    okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
                    okhttp3.internal.platform.o oVar2 = okhttp3.internal.platform.o.a;
                    String str = "Http2Connection.Listener failure for " + ((n) this.f).c;
                    oVar2.getClass();
                    okhttp3.internal.platform.o.i(4, str, e);
                    try {
                        ((v) this.g).c(a.PROTOCOL_ERROR, e);
                    } catch (IOException unused) {
                    }
                }
                return -1L;
            default:
                W w = (W) this.f;
                z settings = (z) this.g;
                Intrinsics.checkNotNullParameter(settings, "settings");
                J j = new J();
                n nVar2 = (n) w.c;
                synchronized (nVar2.w) {
                    synchronized (nVar2) {
                        try {
                            z zVar = nVar2.q;
                            z zVar2 = new z();
                            zVar2.b(zVar);
                            zVar2.b(settings);
                            j.a = zVar2;
                            jA = zVar2.a() - zVar.a();
                            vVarArr = (jA == 0 || nVar2.b.isEmpty()) ? null : (v[]) nVar2.b.values().toArray(new v[0]);
                            z zVar3 = (z) j.a;
                            Intrinsics.checkNotNullParameter(zVar3, "<set-?>");
                            nVar2.q = zVar3;
                            nVar2.j.c(new h(i, nVar2, j, nVar2.c + " onSettings"), 0L);
                            Unit unit = Unit.a;
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                    try {
                        nVar2.w.a((z) j.a);
                    } catch (IOException e2) {
                        nVar2.d(e2);
                    }
                    Unit unit2 = Unit.a;
                }
                if (vVarArr != null) {
                    int length = vVarArr.length;
                    while (i < length) {
                        v vVar = vVarArr[i];
                        synchronized (vVar) {
                            vVar.f += jA;
                            if (jA > 0) {
                                vVar.notifyAll();
                            }
                            Unit unit3 = Unit.a;
                        }
                        i++;
                    }
                }
                return -1L;
        }
    }
}
