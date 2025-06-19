package androidx.work;

import androidx.appcompat.app.ExecutorC0060p;
import androidx.camera.camera2.internal.C0143u;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigException;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.Executor;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class H implements androidx.concurrent.futures.j, com.google.android.gms.tasks.a {
    public final /* synthetic */ Object a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ H(Object obj, Object obj2, Object obj3, Object obj4, Object obj5) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
        this.e = obj5;
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i completer) {
        Intrinsics.checkNotNullParameter(completer, "completer");
        ((ExecutorC0060p) this.a).execute(new I((B) this.b, (String) this.c, (Function0) this.d, (Y) this.e, completer, 0));
        return Unit.a;
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        Date date = (Date) this.d;
        HashMap map = (HashMap) this.e;
        com.google.firebase.remoteconfig.internal.e eVar = (com.google.firebase.remoteconfig.internal.e) this.a;
        eVar.getClass();
        com.google.android.gms.tasks.m mVar = (com.google.android.gms.tasks.m) this.b;
        if (!mVar.l()) {
            return S3.h(new FirebaseRemoteConfigClientException("Firebase Installations failed to get installation ID for fetch.", mVar.g()));
        }
        com.google.android.gms.tasks.m mVar2 = (com.google.android.gms.tasks.m) this.c;
        if (!mVar2.l()) {
            return S3.h(new FirebaseRemoteConfigClientException("Firebase Installations failed to get installation auth token for fetch.", mVar2.g()));
        }
        try {
            com.google.firebase.remoteconfig.internal.d dVarA = eVar.a((String) mVar.h(), ((com.google.firebase.installations.a) mVar2.h()).a, date, map);
            if (dVarA.a != 0) {
                return S3.i(dVarA);
            }
            com.google.firebase.remoteconfig.internal.b bVar = eVar.e;
            com.google.firebase.remoteconfig.internal.c cVar = dVarA.b;
            bVar.getClass();
            androidx.work.impl.A a = new androidx.work.impl.A(4, bVar, cVar);
            Executor executor = bVar.a;
            return S3.g(executor, a).n(executor, new C0143u(26, bVar, cVar)).n(eVar.c, new com.google.android.material.search.a(dVarA, 14));
        } catch (FirebaseRemoteConfigException e) {
            return S3.h(e);
        }
    }
}
