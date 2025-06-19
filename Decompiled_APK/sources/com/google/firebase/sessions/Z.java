package com.google.firebase.sessions;

import android.util.Log;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class Z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ String k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z(String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Z(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            com.google.firebase.sessions.api.c cVar = com.google.firebase.sessions.api.c.a;
            this.j = 1;
            obj = cVar.b(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        Collection<com.google.firebase.crashlytics.internal.common.h> collectionValues = ((Map) obj).values();
        String str = this.k;
        for (com.google.firebase.crashlytics.internal.common.h hVar : collectionValues) {
            com.google.firebase.sessions.api.e eVar = new com.google.firebase.sessions.api.e(str);
            hVar.getClass();
            Objects.toString(eVar);
            Log.isLoggable("FirebaseCrashlytics", 3);
            com.google.firebase.crashlytics.internal.common.g gVar = hVar.b;
            synchronized (gVar) {
                if (!Objects.equals(gVar.c, str)) {
                    com.google.firebase.crashlytics.internal.common.g.a(gVar.a, gVar.b, str);
                    gVar.c = str;
                }
            }
            com.google.firebase.sessions.api.d.a.toString();
        }
        return Unit.a;
    }
}
