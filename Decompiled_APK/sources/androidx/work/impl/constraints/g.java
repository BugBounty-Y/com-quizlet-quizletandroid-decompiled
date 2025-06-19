package androidx.work.impl.constraints;

import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.os.Build;
import androidx.compose.foundation.C0473q;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.C1425f;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.F1;
import java.io.UnsupportedEncodingException;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1425f l;
    public final /* synthetic */ h m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(C1425f c1425f, h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = c1425f;
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.l, this.m, hVar);
        gVar.k = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        C0473q c0473q;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            u uVar = (u) this.k;
            NetworkRequest networkRequest = this.l.b.a;
            if (networkRequest == null) {
                t tVar = (t) uVar;
                tVar.getClass();
                tVar.n0(null);
                return Unit.a;
            }
            androidx.compose.ui.viewinterop.b onConstraintState = new androidx.compose.ui.viewinterop.b(8, E.A(uVar, null, null, new f(this.m, uVar, null), 3), uVar);
            if (Build.VERSION.SDK_INT >= 30) {
                k kVar = k.a;
                ConnectivityManager connManager = this.m.a;
                kVar.getClass();
                Intrinsics.checkNotNullParameter(connManager, "connManager");
                Intrinsics.checkNotNullParameter(networkRequest, "networkRequest");
                Intrinsics.checkNotNullParameter(onConstraintState, "onConstraintState");
                synchronized (k.b) {
                    try {
                        LinkedHashMap linkedHashMap = k.c;
                        boolean zIsEmpty = linkedHashMap.isEmpty();
                        linkedHashMap.put(networkRequest, onConstraintState);
                        if (zIsEmpty) {
                            z zVarC = z.c();
                            int i2 = o.a;
                            zVarC.getClass();
                            connManager.registerDefaultNetworkCallback(kVar);
                        }
                        Unit unit = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                c0473q = new C0473q(networkRequest, connManager, kVar, 18);
            } else {
                int i3 = d.c;
                ConnectivityManager connManager2 = this.m.a;
                Intrinsics.checkNotNullParameter(connManager2, "connManager");
                Intrinsics.checkNotNullParameter(networkRequest, "networkRequest");
                Intrinsics.checkNotNullParameter(onConstraintState, "onConstraintState");
                d dVar = new d(onConstraintState);
                F f = new F();
                try {
                    z zVarC2 = z.c();
                    int i4 = o.a;
                    zVarC2.getClass();
                    connManager2.registerNetworkCallback(networkRequest, dVar);
                    f.a = true;
                } catch (RuntimeException e) {
                    String name = e.getClass().getName();
                    Intrinsics.checkNotNullExpressionValue(name, "ex.javaClass.name");
                    if (!D.k(name, "TooManyRequestsException", false)) {
                        throw e;
                    }
                    z zVarC3 = z.c();
                    int i5 = o.a;
                    zVarC3.getClass();
                    onConstraintState.invoke(new b(7));
                }
                c0473q = new C0473q(f, connManager2, dVar, 17);
            }
            e eVar = new e(0, c0473q);
            this.j = 1;
            if (F1.a(uVar, eVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
