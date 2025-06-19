package com.google.firebase.sessions;

import android.util.Log;
import androidx.datastore.core.InterfaceC1076h;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ L k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(L l, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                InterfaceC1076h interfaceC1076h = this.k.b;
                J j = new J(this.l, null);
                this.j = 1;
                if (S6.d(interfaceC1076h, j, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
        } catch (IOException e) {
            Log.w("FirebaseSessionsRepo", "Failed to update session Id: " + e);
        }
        return Unit.a;
    }
}
