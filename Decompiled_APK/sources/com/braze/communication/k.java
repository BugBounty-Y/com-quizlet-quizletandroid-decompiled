package com.braze.communication;

import com.braze.managers.BrazeGeofenceManager;
import com.braze.managers.i0;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.reflect.o;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ArrayList b;

    public /* synthetic */ k(int i, ArrayList arrayList) {
        this.a = i;
        this.b = arrayList;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.a(this.b);
            case 1:
                return BrazeGeofenceManager.registerGeofences$lambda$37$lambda$33(this.b);
            case 2:
                return i0.a((List) this.b);
            case 3:
                return this.b;
            case 4:
                ArrayList arrayList = this.b;
                if (arrayList.isEmpty()) {
                    return K.a;
                }
                return arrayList.subList((((CharSequence) CollectionsKt.L(arrayList)).length() != 0 || arrayList.size() <= 1) ? 0 : 1, ((CharSequence) CollectionsKt.U(arrayList)).length() == 0 ? B.i(arrayList) : 1 + B.i(arrayList));
            default:
                return ((o) this.b.get(0)).d();
        }
    }
}
