package com.google.firebase.sessions;

import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.LinkedBlockingDeque;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class b0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.explanations.textbook.a k;
    public final /* synthetic */ ArrayList l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b0(com.quizlet.data.repository.explanations.textbook.a aVar, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = aVar;
        this.l = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws RemoteException {
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
        Map map = (Map) obj;
        if (!map.isEmpty()) {
            Collection collectionValues = map.values();
            if (!(collectionValues instanceof Collection) || !collectionValues.isEmpty()) {
                Iterator it2 = collectionValues.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    }
                    if (((com.google.firebase.crashlytics.internal.common.h) it2.next()).a.n()) {
                        ArrayList arrayList = this.l;
                        com.quizlet.data.repository.explanations.textbook.a aVar2 = this.k;
                        for (Message message : CollectionsKt.n0(CollectionsKt.J(kotlin.collections.B.k(com.quizlet.data.repository.explanations.textbook.a.a(aVar2, arrayList, 2), com.quizlet.data.repository.explanations.textbook.a.a(aVar2, arrayList, 1))), new a0())) {
                            Messenger messenger = (Messenger) aVar2.b;
                            LinkedBlockingDeque linkedBlockingDeque = (LinkedBlockingDeque) aVar2.c;
                            if (messenger != null) {
                                try {
                                    int i2 = message.what;
                                    messenger.send(message);
                                } catch (RemoteException e) {
                                    Log.w("SessionLifecycleClient", "Unable to deliver message: " + message.what, e);
                                    if (linkedBlockingDeque.offer(message)) {
                                        linkedBlockingDeque.size();
                                    }
                                }
                            } else if (linkedBlockingDeque.offer(message)) {
                                int i3 = message.what;
                                linkedBlockingDeque.size();
                            } else {
                                int i4 = message.what;
                            }
                        }
                    }
                }
            }
        }
        return Unit.a;
    }
}
