package androidx.camera.core.impl.utils.futures;

import androidx.activity.RunnableC0041m;
import com.google.android.gms.internal.mlkit_vision_barcode.T;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements androidx.concurrent.futures.j {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.common.util.concurrent.e b;

    public /* synthetic */ g(int i, com.google.common.util.concurrent.e eVar) {
        this.a = i;
        this.b = eVar;
    }

    @Override // androidx.concurrent.futures.j
    public final Object d(androidx.concurrent.futures.i iVar) {
        switch (this.a) {
            case 0:
                RunnableC0041m runnableC0041m = new RunnableC0041m(iVar, 17);
                androidx.camera.core.impl.utils.executor.a aVarA = T.a();
                com.google.common.util.concurrent.e eVar = this.b;
                eVar.a(runnableC0041m, aVarA);
                return "transformVoidFuture [" + eVar + "]";
            default:
                androidx.camera.core.impl.utils.executor.a aVarA2 = T.a();
                com.google.common.util.concurrent.e eVar2 = this.b;
                i.e(false, eVar2, iVar, aVarA2);
                return "nonCancellationPropagating[" + eVar2 + "]";
        }
    }
}
