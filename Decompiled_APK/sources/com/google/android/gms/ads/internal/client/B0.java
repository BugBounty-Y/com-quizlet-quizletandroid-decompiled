package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C2278kl;
import com.google.android.gms.internal.ads.K9;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.zzblu;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class B0 extends AbstractBinderC2814x5 implements K9 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B0(Object obj, int i) {
        super("com.google.android.gms.ads.internal.initialization.IInitializationCallback");
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.K9
    public final void S2(List list) {
        ArrayList arrayList;
        switch (this.a) {
            case 0:
                C0 c0 = (C0) this.b;
                synchronized (c0.a) {
                    c0.c = false;
                    c0.d = true;
                    arrayList = new ArrayList(c0.b);
                    c0.b.clear();
                }
                L9 it2 = C0.a(list);
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    com.quizlet.quizletandroid.initializers.ads.a aVar = (com.quizlet.quizletandroid.initializers.ads.a) arrayList.get(i);
                    aVar.getClass();
                    Intrinsics.checkNotNullParameter(it2, "it");
                    timber.log.c.a.g("Mobile ads initialized", new Object[0]);
                    aVar.a.invoke();
                }
                return;
            default:
                ((C2278kl) this.b).b(list);
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(zzblu.CREATOR);
        AbstractC2857y5.b(parcel);
        S2(arrayListCreateTypedArrayList);
        parcel2.writeNoException();
        return true;
    }
}
