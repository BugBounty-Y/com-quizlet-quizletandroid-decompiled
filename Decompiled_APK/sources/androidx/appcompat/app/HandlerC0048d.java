package androidx.appcompat.app;

import android.content.DialogInterface;
import android.content.Intent;
import android.media.MediaCodec;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.BE;
import com.google.android.gms.internal.ads.CE;
import com.google.firebase.sessions.Z;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.ArrayList;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.app.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class HandlerC0048d extends Handler {
    public final /* synthetic */ int a;
    public Object b;

    @Override // android.os.Handler
    public final void handleMessage(Message message) throws MediaCodec.CryptoException {
        int size;
        com.quizlet.data.interactor.school.b[] bVarArr;
        BE be;
        String string;
        switch (this.a) {
            case 0:
                int i = message.what;
                if (i == -3 || i == -2 || i == -1) {
                    ((DialogInterface.OnClickListener) message.obj).onClick((DialogInterface) ((WeakReference) this.b).get(), message.what);
                    return;
                } else {
                    if (i != 1) {
                        return;
                    }
                    ((DialogInterface) message.obj).dismiss();
                    return;
                }
            case 1:
                if (message.what != 1) {
                    super.handleMessage(message);
                    return;
                }
                androidx.localbroadcastmanager.content.b bVar = (androidx.localbroadcastmanager.content.b) this.b;
                while (true) {
                    synchronized (bVar.b) {
                        try {
                            size = bVar.d.size();
                            if (size <= 0) {
                                return;
                            }
                            bVarArr = new com.quizlet.data.interactor.school.b[size];
                            bVar.d.toArray(bVarArr);
                            bVar.d.clear();
                        } finally {
                        }
                    }
                    for (int i2 = 0; i2 < size; i2++) {
                        com.quizlet.data.interactor.school.b bVar2 = bVarArr[i2];
                        int size2 = ((ArrayList) bVar2.c).size();
                        for (int i3 = 0; i3 < size2; i3++) {
                            androidx.localbroadcastmanager.content.a aVar = (androidx.localbroadcastmanager.content.a) ((ArrayList) bVar2.c).get(i3);
                            if (!aVar.d) {
                                aVar.b.onReceive(bVar.a, (Intent) bVar2.b);
                            }
                        }
                    }
                }
            case 2:
                if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(message, "message");
                    com.facebook.internal.D d = (com.facebook.internal.D) this.b;
                    d.getClass();
                    Intrinsics.checkNotNullParameter(message, "message");
                    if (message.what == d.g) {
                        Bundle data = message.getData();
                        if (data.getString("com.facebook.platform.status.ERROR_TYPE") != null) {
                            d.a(null);
                        } else {
                            d.a(data);
                        }
                        try {
                            d.a.unbindService(d);
                            return;
                        } catch (IllegalArgumentException unused) {
                            return;
                        }
                    }
                    return;
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                    return;
                }
            case 3:
                CE ce = (CE) this.b;
                int i4 = message.what;
                if (i4 == 1) {
                    be = (BE) message.obj;
                    try {
                        ce.a.queueInputBuffer(be.a, 0, be.b, be.d, be.e);
                    } catch (RuntimeException e) {
                        AbstractC1981ds.h(ce.d, e);
                    }
                } else if (i4 != 2) {
                    be = null;
                    if (i4 == 3) {
                        ce.e.c();
                    } else if (i4 != 4) {
                        AbstractC1981ds.h(ce.d, new IllegalStateException(String.valueOf(message.what)));
                    } else {
                        try {
                            ce.a.setParameters((Bundle) message.obj);
                        } catch (RuntimeException e2) {
                            AbstractC1981ds.h(ce.d, e2);
                        }
                    }
                } else {
                    be = (BE) message.obj;
                    int i5 = be.a;
                    MediaCodec.CryptoInfo cryptoInfo = be.c;
                    long j = be.d;
                    int i6 = be.e;
                    try {
                        synchronized (CE.h) {
                            ce.a.queueSecureInputBuffer(i5, 0, cryptoInfo, j, i6);
                        }
                    } catch (RuntimeException e3) {
                        AbstractC1981ds.h(ce.d, e3);
                    }
                }
                if (be != null) {
                    ArrayDeque arrayDeque = CE.g;
                    synchronized (arrayDeque) {
                        arrayDeque.add(be);
                    }
                    return;
                }
                return;
            default:
                Intrinsics.checkNotNullParameter(message, "msg");
                if (message.what != 3) {
                    Log.w("SessionLifecycleClient", "Received unexpected event from the SessionLifecycleService: " + message);
                    super.handleMessage(message);
                    return;
                }
                Bundle data2 = message.getData();
                if (data2 == null || (string = data2.getString("SessionUpdateExtra")) == null) {
                    string = "";
                }
                kotlinx.coroutines.E.A(kotlinx.coroutines.E.c((CoroutineContext) this.b), null, null, new Z(string, null), 3);
                return;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ HandlerC0048d(Object obj, Looper looper, int i) {
        super(looper);
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public HandlerC0048d(CoroutineContext backgroundDispatcher) {
        super(Looper.getMainLooper());
        this.a = 4;
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        this.b = backgroundDispatcher;
    }

    public HandlerC0048d(com.facebook.internal.D d) {
        this.a = 2;
        this.b = d;
    }
}
