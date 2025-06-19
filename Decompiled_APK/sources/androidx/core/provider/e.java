package androidx.core.provider;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.ads.zzbyz;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;

/* loaded from: classes.dex */
public final class e implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    public /* synthetic */ e(com.google.android.gms.ads.nonagon.signalgeneration.i iVar, zzbyz zzbyzVar, int i, Bundle bundle) {
        this.a = 2;
        this.b = iVar;
        this.c = zzbyzVar;
        this.d = i;
        this.e = bundle;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
            case 0:
                Object[] objArr = {(d) this.e};
                ArrayList arrayList = new ArrayList(1);
                Object obj = objArr[0];
                Objects.requireNonNull(obj);
                arrayList.add(obj);
                return g.b((String) this.b, (Context) this.c, Collections.unmodifiableList(arrayList), this.d);
            case 1:
                try {
                    return g.b((String) this.b, (Context) this.c, (List) this.e, this.d);
                } catch (Throwable unused) {
                    return new f(-3);
                }
            default:
                com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.b;
                Context context = iVar.c;
                zzbyz zzbyzVar = (zzbyz) this.c;
                return iVar.e4(context, zzbyzVar.a, zzbyzVar.b, zzbyzVar.c, zzbyzVar.d, this.d, zzbyzVar.f, (Bundle) this.e, zzbyzVar);
        }
    }

    public /* synthetic */ e(String str, Context context, Object obj, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = context;
        this.e = obj;
        this.d = i;
    }
}
