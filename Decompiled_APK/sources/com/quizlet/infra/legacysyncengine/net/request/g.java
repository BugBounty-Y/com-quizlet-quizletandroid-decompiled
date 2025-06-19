package com.quizlet.infra.legacysyncengine.net.request;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.exceptions.OnErrorNotImplementedException;
import io.reactivex.rxjava3.exceptions.UndeliverableException;
import java.io.IOException;
import java.net.SocketException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;

    public /* synthetic */ g(int i) {
        this.a = i;
    }

    private final void a(Object obj) {
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Throwable {
        switch (this.a) {
            case 0:
                timber.log.c.a((Throwable) obj);
                return;
            case 1:
                Throwable t = (Throwable) obj;
                Intrinsics.checkNotNullParameter(t, "t");
                if (t instanceof UndeliverableException) {
                    timber.log.c.a.f(t.getCause(), "Rx error: UndeliverableException", new Object[0]);
                    return;
                } else {
                    if (!(t instanceof IOException) && !(t instanceof SocketException) && !(t instanceof InterruptedException)) {
                        throw t;
                    }
                    timber.log.c.a.q(t, "DEV: Check to see if you should be handling this", new Object[0]);
                    return;
                }
            case 2:
                return;
            default:
                C7.c(new OnErrorNotImplementedException((Throwable) obj));
                return;
        }
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return "EmptyConsumer";
            default:
                return super.toString();
        }
    }
}
